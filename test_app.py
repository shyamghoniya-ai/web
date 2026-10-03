import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import parse_qs
from unittest.mock import patch

from app import create_app


class MorrowApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "test.sqlite3"
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "DATABASE": str(database_path),
            "ADMIN_SECRET": "shyamowner1",
            "RATELIMIT_STORAGE_URI": "memory://",
        })
        self.client = self.app.test_client()
        self.database_path = database_path
        self.csrf_token = self.client.get("/api/csrf").get_json()["csrf_token"]

    def tearDown(self):
        self.temporary_directory.cleanup()

    def post(self, path, payload, token=None):
        return self.client.post(
            path,
            json=payload,
            headers={"X-CSRF-Token": token or self.csrf_token},
        )

    def register(self):
        response = self.post("/api/register", {
            "name": "Sam Taylor",
            "email": "sam@example.com",
            "password": "correct-horse-42",
            "accept_terms": True,
        })
        self.assertEqual(response.status_code, 201)
        result = response.get_json()
        self.csrf_token = result["csrf_token"]
        return result

    def admin_login(self, password="shyamowner1"):
        response = self.client.post("/admin/login", data={
            "password": password,
            "csrf_token": self.csrf_token,
        })
        if password == "shyamowner1" and response.status_code == 302:
            self.csrf_token = self.client.get("/api/csrf").get_json()["csrf_token"]
        return response

    def create_booking(self):
        self.register()
        response = self.post("/api/bookings", {
            "service": "Home cleaning",
            "address": "12 M G Road, Junagadh",
            "phone": "+91 98765 43210",
            "preferred_date": (date.today() + timedelta(days=1)).isoformat(),
            "preferred_window": "afternoon",
            "notes": "Please call before arriving.",
        })
        self.assertEqual(response.status_code, 201)
        return response.get_json()["booking"]["id"]

    def test_production_requires_secrets_but_allows_single_instance_rate_limits(self):
        configurations = [
            ({"APP_ENV": "production"}, "MORROW_SECRET_KEY"),
            ({
                "APP_ENV": "production",
                "MORROW_SECRET_KEY": "s" * 32,
            }, "MORROW_ADMIN_SECRET"),
            ({
                "APP_ENV": "production",
                "MORROW_SECRET_KEY": "s" * 32,
                "MORROW_ADMIN_SECRET": "too-short",
            }, "MORROW_ADMIN_SECRET"),
        ]
        for environment, expected_error in configurations:
            with self.subTest(expected_error=expected_error), patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    create_app({"TESTING": True, "DATABASE": ":memory:"})

        with patch.dict(os.environ, {
            "APP_ENV": "production",
            "MORROW_SECRET_KEY": "s" * 32,
            "MORROW_ADMIN_SECRET": "a" * 16,
            "MORROW_RATE_LIMIT_STORAGE": "memory://",
        }, clear=True):
            production_app = create_app({"TESTING": True, "DATABASE": ":memory:"})
            self.assertEqual(production_app.config["RATELIMIT_STORAGE_URI"], "memory://")
            production_app.extensions["memory_database_keeper"].close()

    def test_security_headers_and_private_api_cache_control(self):
        response = self.client.get("/api/session")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin-when-cross-origin")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_register_login_and_session(self):
        result = self.register()
        self.assertEqual(result["user"]["email"], "sam@example.com")
        self.assertEqual(self.client.get("/api/session").get_json()["user"]["name"], "Sam Taylor")

        database = sqlite3.connect(self.database_path)
        try:
            password_hash = database.execute("SELECT password_hash FROM users").fetchone()[0]
        finally:
            database.close()
        self.assertNotEqual(password_hash, "correct-horse-42")

        login_client = self.app.test_client()
        csrf_token = login_client.get("/api/csrf").get_json()["csrf_token"]
        response = login_client.post(
            "/api/login",
            json={"email": "sam@example.com", "password": "correct-horse-42"},
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(login_client.get("/api/session").get_json()["user"]["id"], result["user"]["id"])

    def test_booking_is_saved_as_pending_and_requires_login(self):
        payload = {
            "service": "Home cleaning",
            "address": "12 M G Road, Junagadh",
            "phone": "+91 98765 43210",
            "preferred_date": (date.today() + timedelta(days=1)).isoformat(),
            "preferred_window": "afternoon",
            "notes": "Please call before arriving.",
        }
        anonymous_response = self.post("/api/bookings", payload)
        self.assertEqual(anonymous_response.status_code, 401)

        self.register()
        response = self.post("/api/bookings", payload)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["booking"]["status"], "pending")
        self.assertEqual(self.client.get("/api/bookings").get_json()["bookings"][0]["service"], "Home cleaning")

    def test_booking_saves_payment_preference_and_accepts_offline_fallback(self):
        self.register()
        payload = {
            "service": "Home cleaning",
            "address": "12 M G Road, Junagadh",
            "phone": "+91 98765 43210",
            "preferred_date": (date.today() + timedelta(days=1)).isoformat(),
            "preferred_window": "afternoon",
            "notes": "Please call before arriving.",
            "payment_method": "offline",
        }
        response = self.post("/api/bookings", payload)
        self.assertEqual(response.status_code, 201)
        booking = response.get_json()["booking"]
        self.assertEqual(booking["payment_method"], "offline")
        self.assertEqual(self.client.get("/api/bookings").get_json()["bookings"][0]["payment_method"], "offline")

    def test_contact_requires_csrf_and_is_persisted(self):
        payload = {"name": "Sam Taylor", "email": "sam@example.com", "message": "Please call me back."}
        missing_token = self.client.post("/api/contact", json=payload)
        self.assertEqual(missing_token.status_code, 400)

        response = self.post("/api/contact", payload)
        self.assertEqual(response.status_code, 201)
        database = sqlite3.connect(self.database_path)
        try:
            saved_message = database.execute("SELECT message FROM contact_messages").fetchone()[0]
        finally:
            database.close()
        self.assertEqual(saved_message, payload["message"])

    def test_registration_rejects_duplicate_email(self):
        self.register()
        response = self.post("/api/register", {
            "name": "Another Person",
            "email": "SAM@example.com",
            "password": "another-password-42",
            "accept_terms": True,
        })
        self.assertEqual(response.status_code, 409)

    def test_logout_clears_account_session(self):
        self.register()

        missing_csrf = self.client.post("/api/logout")
        self.assertEqual(missing_csrf.status_code, 400)

        response = self.post("/api/logout", {})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.get("/api/session").get_json()["user"])

    def test_google_link_requires_oauth_configuration(self):
        self.register()
        self.assertFalse(self.client.get("/api/google/config").get_json()["available"])

        response = self.client.get("/auth/google/connect")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/?google=unavailable")
        self.assertEqual(self.client.post("/api/connect-google", json={"google_email": "sam@gmail.com"}).status_code, 404)

        database = sqlite3.connect(self.database_path)
        try:
            linked_email = database.execute("SELECT google_email FROM users").fetchone()[0]
        finally:
            database.close()
        self.assertIsNone(linked_email)

    def test_about_page_explains_services_and_request_process(self):
        response = self.client.get("/about")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("About Morrow", html)
        self.assertIn("Junagadh", html)
        self.assertIn("final quote", html)
        self.assertIn("/terms", html)

    def test_agent_application_requires_consent_and_is_visible_to_owner(self):
        payload = {
            "name": "Ravi Patel",
            "email": "ravi@example.com",
            "phone": "+91 98765 43210",
            "service_area": "Junagadh",
            "services": ["Home cleaning", "Deep cleaning"],
            "experience": "Three years of residential cleaning work.",
            "contact_consent": False,
        }
        no_consent = self.post("/api/agent-applications", payload)
        self.assertEqual(no_consent.status_code, 400)

        payload["contact_consent"] = True
        response = self.post("/api/agent-applications", payload)
        self.assertEqual(response.status_code, 201)

        database = sqlite3.connect(self.database_path)
        try:
            application = database.execute(
                "SELECT name, services_json, status FROM agent_applications"
            ).fetchone()
        finally:
            database.close()
        self.assertEqual(application[0], "Ravi Patel")
        self.assertEqual(json.loads(application[1]), ["Deep cleaning", "Home cleaning"])
        self.assertEqual(application[2], "new")

        with self.client.session_transaction() as owner_session:
            owner_session["admin_authenticated"] = True
        dashboard = self.client.get("/admin")
        self.assertIn("Ravi Patel", dashboard.get_data(as_text=True))

    def test_owner_quote_enables_payment_only_when_razorpay_is_configured(self):
        booking_id = self.create_booking()
        with self.client.session_transaction() as owner_session:
            owner_session["admin_authenticated"] = True

        response = self.client.post(f"/admin/bookings/{booking_id}/quote", data={
            "csrf_token": self.csrf_token,
            "quote_rupees": "500",
        })
        self.assertEqual(response.status_code, 302)
        booking = self.client.get("/api/bookings").get_json()["bookings"][0]
        self.assertEqual(booking["quote_before_discount_paise"], 50000)
        self.assertEqual(booking["discount_amount_paise"], 5000)
        self.assertEqual(booking["quote_amount_paise"], 45000)
        self.assertEqual(booking["status"], "awaiting_payment")
        self.assertFalse(self.client.get("/api/payments/config").get_json()["available"])

        payment = self.post(f"/api/bookings/{booking_id}/payment/order", {})
        self.assertEqual(payment.status_code, 503)

    def test_accepting_request_sends_sms_with_discounted_quote(self):
        booking_id = self.create_booking()
        self.app.config.update(
            TWILIO_ACCOUNT_SID="ACtestaccount",
            TWILIO_AUTH_TOKEN="test-token",
            TWILIO_FROM_NUMBER="+15551234567",
            PUBLIC_URL="https://morrow.example",
        )
        with self.client.session_transaction() as owner_session:
            owner_session["admin_authenticated"] = True

        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with patch("app.urlopen", return_value=FakeResponse()) as send_sms:
            response = self.client.post(f"/admin/bookings/{booking_id}/quote", data={
                "csrf_token": self.csrf_token,
                "quote_rupees": "500",
            })

        self.assertEqual(response.status_code, 302)
        sms_request = send_sms.call_args.args[0]
        sms_payload = parse_qs(sms_request.data.decode())
        self.assertEqual(sms_payload["To"], ["+919876543210"])
        self.assertIn("accepted your Home cleaning request", sms_payload["Body"][0])
        self.assertIn("Please pay INR 450.00 now", sms_payload["Body"][0])
        self.assertIn(f"https://morrow.example/?booking={booking_id}", sms_payload["Body"][0])
        self.assertIn("SMS confirmation sent", self.client.get("/admin").get_data(as_text=True))

    def test_first_request_discount_only_applies_to_earliest_booking(self):
        first_booking_id = self.create_booking()
        second_response = self.post("/api/bookings", {
            "service": "Deep cleaning",
            "address": "12 M G Road, Junagadh",
            "phone": "+91 98765 43210",
            "preferred_date": (date.today() + timedelta(days=2)).isoformat(),
            "preferred_window": "morning",
            "notes": "",
        })
        self.assertEqual(second_response.status_code, 201)
        second_booking_id = second_response.get_json()["booking"]["id"]
        with self.client.session_transaction() as owner_session:
            owner_session["admin_authenticated"] = True

        for booking_id in (first_booking_id, second_booking_id):
            self.client.post(f"/admin/bookings/{booking_id}/quote", data={
                "csrf_token": self.csrf_token,
                "quote_rupees": "500",
            })

        bookings = self.client.get("/api/bookings").get_json()["bookings"]
        by_id = {booking["id"]: booking for booking in bookings}
        self.assertEqual(by_id[first_booking_id]["discount_amount_paise"], 5000)
        self.assertEqual(by_id[first_booking_id]["quote_amount_paise"], 45000)
        self.assertEqual(by_id[second_booking_id]["discount_amount_paise"], 0)
        self.assertEqual(by_id[second_booking_id]["quote_amount_paise"], 50000)

    def test_razorpay_payment_is_signature_and_capture_verified(self):
        self.app.config["RAZORPAY_KEY_ID"] = "rzp_test_public"
        self.app.config["RAZORPAY_KEY_SECRET"] = "test-only-secret"
        booking_id = self.create_booking()
        with self.client.session_transaction() as owner_session:
            owner_session["admin_authenticated"] = True
        self.client.post(f"/admin/bookings/{booking_id}/quote", data={
            "csrf_token": self.csrf_token,
            "quote_rupees": "500",
        })

        class FakeResponse:
            def __init__(self, body):
                self.body = json.dumps(body).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

        with patch("app.urlopen", return_value=FakeResponse({"id": "order_test123"})):
            order = self.post(f"/api/bookings/{booking_id}/payment/order", {})
        self.assertEqual(order.status_code, 200)
        self.assertEqual(order.get_json()["amount"], 45000)

        payment_id = "pay_test123"
        signature = hmac.new(
            b"test-only-secret",
            f"order_test123|{payment_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        payload = {
            "razorpay_order_id": "order_test123",
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        }
        invalid_signature = {**payload, "razorpay_signature": "0" * 64}
        self.assertEqual(
            self.post(f"/api/bookings/{booking_id}/payment/verify", invalid_signature).status_code,
            400,
        )

        captured_payment = {
            "order_id": "order_test123",
            "amount": 45000,
            "currency": "INR",
            "status": "captured",
        }
        with patch("app.urlopen", return_value=FakeResponse(captured_payment)):
            verified = self.post(f"/api/bookings/{booking_id}/payment/verify", payload)
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.get_json()["success"])

        database = sqlite3.connect(self.database_path)
        try:
            state = database.execute(
                "SELECT status, payment_status, payment_id FROM bookings WHERE id = ?",
                (booking_id,),
            ).fetchone()
        finally:
            database.close()
        self.assertEqual(state, ("paid", "paid", payment_id))

    def test_admin_page_lists_messages_and_bookings(self):
        self.register()
        self.post("/api/contact", {"name": "Sam Taylor", "email": "sam@example.com", "message": "Need help with plumbing."})
        self.post("/api/bookings", {
            "service": "Home cleaning",
            "address": "12 M G Road, Junagadh",
            "phone": "+91 98765 43210",
            "preferred_date": (date.today() + timedelta(days=1)).isoformat(),
            "preferred_window": "afternoon",
            "notes": "Please call before arriving.",
        })

        bypass_response = self.client.get("/admin?token=shyamowner1")
        self.assertIn("Enter admin password", bypass_response.get_data(as_text=True))

        self.admin_login()
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Need help with plumbing.", html)
        self.assertIn("Home cleaning", html)

    def test_admin_dashboard_requires_password_before_access(self):
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter admin password", response.get_data(as_text=True))

        missing_csrf = self.client.post("/admin/login", data={"password": "shyamowner1"})
        self.assertEqual(missing_csrf.status_code, 400)

        wrong_password = self.admin_login("incorrect-password")
        self.assertEqual(wrong_password.status_code, 302)
        self.assertIn("Enter admin password", self.client.get("/admin").get_data(as_text=True))

        previous_csrf_token = self.csrf_token
        login_response = self.admin_login()
        self.assertEqual(login_response.status_code, 302)
        self.assertNotEqual(self.csrf_token, previous_csrf_token)

        dashboard_response = self.client.get("/admin")
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIn("Morrow owner dashboard", dashboard_response.get_data(as_text=True))

        missing_logout_csrf = self.client.post("/admin/leave")
        self.assertEqual(missing_logout_csrf.status_code, 400)

        leave_response = self.client.post("/admin/leave", data={"csrf_token": self.csrf_token})
        self.assertEqual(leave_response.status_code, 302)
        self.assertEqual(leave_response.headers["Location"], "/")
        reopened_dashboard = self.client.get("/admin")
        self.assertIn("Enter admin password", reopened_dashboard.get_data(as_text=True))

    def test_admin_dashboard_stays_disabled_without_configured_secret(self):
        self.app.config["ADMIN_SECRET"] = ""
        response = self.client.get("/admin")
        self.assertIn("Set MORROW_ADMIN_SECRET", response.get_data(as_text=True))

        login_response = self.client.post("/admin/login", data={
            "csrf_token": self.csrf_token,
            "password": "shyamowner1",
        })
        self.assertEqual(login_response.status_code, 503)


if __name__ == "__main__":
    unittest.main()