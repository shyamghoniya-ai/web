import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import date
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from authlib.integrations.flask_client import OAuth
from flask import Flask, g, jsonify, redirect, render_template_string, request, send_from_directory, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
SERVICE_NAMES = {
    "Plumbing & repairs",
    "Electrical help",
    "Home cleaning",
    "Painting & refresh",
    "Heating & cooling",
    "Handyman visits",
    "Appliance repair",
    "Deep cleaning",
    "Window washing",
    "Furniture assembly",
    "Smart home setup",
    "Lawn & garden care",
}
TIME_WINDOWS = {"morning", "afternoon", "evening"}
FIRST_BOOKING_DISCOUNT_PERCENT = 10


def create_app(test_config=None):
    configured_secret = os.environ.get("MORROW_SECRET_KEY")
    environment = os.environ.get("APP_ENV", "development").lower()

    admin_secret = os.environ.get("MORROW_ADMIN_SECRET", "")
    if test_config and "ADMIN_SECRET" in test_config:
        admin_secret = test_config["ADMIN_SECRET"]

    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=configured_secret or secrets.token_hex(32),
        DATABASE=os.environ.get("MORROW_DATABASE", str(BASE_DIR / "instance" / "morrow.sqlite3")),
        ADMIN_SECRET=admin_secret,
        RAZORPAY_KEY_ID=os.environ.get("MORROW_RAZORPAY_KEY_ID", ""),
        RAZORPAY_KEY_SECRET=os.environ.get("MORROW_RAZORPAY_KEY_SECRET", ""),
        GOOGLE_CLIENT_ID=os.environ.get("MORROW_GOOGLE_CLIENT_ID", ""),
        GOOGLE_CLIENT_SECRET=os.environ.get("MORROW_GOOGLE_CLIENT_SECRET", ""),
        TWILIO_ACCOUNT_SID=os.environ.get("MORROW_TWILIO_ACCOUNT_SID", ""),
        TWILIO_AUTH_TOKEN=os.environ.get("MORROW_TWILIO_AUTH_TOKEN", ""),
        TWILIO_FROM_NUMBER=os.environ.get("MORROW_TWILIO_FROM_NUMBER", ""),
        TWILIO_MESSAGING_SERVICE_SID=os.environ.get("MORROW_TWILIO_MESSAGING_SERVICE_SID", ""),
        PUBLIC_URL=os.environ.get("MORROW_PUBLIC_URL", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=environment == "production",
        MAX_CONTENT_LENGTH=16 * 1024,
        RATELIMIT_STORAGE_URI=os.environ.get("MORROW_RATE_LIMIT_STORAGE", "memory://"),
    )
    if test_config:
        app.config.update(test_config)

    if environment == "production":
        if not configured_secret or len(configured_secret) < 32:
            raise RuntimeError("Set a random MORROW_SECRET_KEY of at least 32 characters in production.")
        if not admin_secret or len(admin_secret) < 16:
            raise RuntimeError("Set a unique MORROW_ADMIN_SECRET of at least 16 characters in production.")

    oauth = OAuth(app)
    google_oauth = None
    if app.config["GOOGLE_CLIENT_ID"].strip() and app.config["GOOGLE_CLIENT_SECRET"].strip():
        google_oauth = oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"].strip(),
            client_secret=app.config["GOOGLE_CLIENT_SECRET"].strip(),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    limiter = Limiter(get_remote_address, app=app, default_limits=[])
    if app.config["DATABASE"] == ":memory:":
        memory_database_uri = f"file:morrow_{secrets.token_hex(16)}?mode=memory&cache=shared"
        app.extensions["memory_database_keeper"] = sqlite3.connect(memory_database_uri, uri=True)
        app.config["DATABASE_URI"] = memory_database_uri

    def get_db():
        if "db" not in g:
            database_path = app.config["DATABASE"]
            if database_path == ":memory:":
                g.db = sqlite3.connect(app.config["DATABASE_URI"], uri=True, timeout=10)
            else:
                Path(database_path).parent.mkdir(parents=True, exist_ok=True)
                g.db = sqlite3.connect(database_path, timeout=10)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    def initialize_database():
        database = get_db()
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                google_email TEXT,
                google_sub TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                service TEXT NOT NULL,
                address TEXT NOT NULL,
                phone TEXT NOT NULL,
                preferred_date TEXT NOT NULL,
                preferred_window TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                payment_method TEXT NOT NULL DEFAULT 'online',
                status TEXT NOT NULL DEFAULT 'pending',
                quote_amount_paise INTEGER,
                quote_before_discount_paise INTEGER,
                discount_amount_paise INTEGER NOT NULL DEFAULT 0,
                razorpay_order_id TEXT,
                payment_id TEXT,
                payment_status TEXT NOT NULL DEFAULT 'unpaid',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS agent_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                service_area TEXT NOT NULL,
                services_json TEXT NOT NULL,
                experience TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        columns = database.execute("PRAGMA table_info(users)").fetchall()
        if not any(column[1] == "google_email" for column in columns):
            database.execute("ALTER TABLE users ADD COLUMN google_email TEXT")
        if not any(column[1] == "google_sub" for column in columns):
            database.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        database.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_unique ON users(google_sub) WHERE google_sub IS NOT NULL"
        )
        database.execute("UPDATE users SET google_email = NULL WHERE google_sub IS NULL AND google_email IS NOT NULL")
        booking_columns = {column[1] for column in database.execute("PRAGMA table_info(bookings)")}
        booking_migrations = {
            "payment_method": "TEXT NOT NULL DEFAULT 'online'",
            "quote_amount_paise": "INTEGER",
            "quote_before_discount_paise": "INTEGER",
            "discount_amount_paise": "INTEGER NOT NULL DEFAULT 0",
            "razorpay_order_id": "TEXT",
            "payment_id": "TEXT",
            "payment_status": "TEXT NOT NULL DEFAULT 'unpaid'",
        }
        for column_name, column_definition in booking_migrations.items():
            if column_name not in booking_columns:
                database.execute(f"ALTER TABLE bookings ADD COLUMN {column_name} {column_definition}")
        database.execute(
            """UPDATE bookings SET quote_before_discount_paise = quote_amount_paise
               WHERE quote_before_discount_paise IS NULL AND quote_amount_paise IS NOT NULL"""
        )
        database.commit()

    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def csrf_is_valid():
        supplied_token = request.headers.get("X-CSRF-Token", "")
        expected_token = session.get("csrf_token", "")
        return bool(supplied_token and expected_token and hmac.compare_digest(supplied_token, expected_token))

    def json_payload():
        payload = request.get_json(silent=True)
        return payload if isinstance(payload, dict) else {}

    def clean_text(value, maximum):
        if not isinstance(value, str):
            return ""
        return value.strip()[:maximum]

    def serialize_user(user):
        if user is None:
            return None
        return {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "google_email": user["google_email"] if user["google_sub"] else None,
            "google_connected": bool(user["google_sub"]),
        }

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        return get_db().execute(
            "SELECT id, name, email, google_email, google_sub FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    def error_response(message, status):
        return jsonify(error=message), status

    def send_booking_acceptance_sms(booking, amount_due_paise):
        account_sid = app.config["TWILIO_ACCOUNT_SID"].strip()
        auth_token = app.config["TWILIO_AUTH_TOKEN"].strip()
        messaging_service_sid = app.config["TWILIO_MESSAGING_SERVICE_SID"].strip()
        from_number = app.config["TWILIO_FROM_NUMBER"].strip()
        public_url = app.config["PUBLIC_URL"].strip().rstrip("/")
        if (
            not account_sid
            or not auth_token
            or not (messaging_service_sid or from_number)
            or not public_url.startswith("https://")
        ):
            return False

        authorization = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode("ascii")
        payment_url = f"{public_url}/?booking={booking['id']}"
        message = (
            f"Morrow accepted your {booking['service']} request (#{booking['id']}). "
            f"Please pay INR {amount_due_paise / 100:.2f} now at {payment_url}. "
            "Sign in to Morrow if asked. Our team will confirm visit timing."
        )
        payload = {
            "To": booking["phone"],
            "Body": message,
        }
        if messaging_service_sid:
            payload["MessagingServiceSid"] = messaging_service_sid
        else:
            payload["From"] = from_number

        provider_request = Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
            data=urlencode(payload).encode(),
            headers={
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urlopen(provider_request, timeout=10) as provider_response:
                return 200 <= provider_response.status < 300
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.exception("Booking acceptance SMS failed for booking %s", booking["id"])
            return False

    @app.teardown_appcontext
    def close_db(_error=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.path.startswith(("/api/", "/admin", "/auth/")):
            response.headers["Cache-Control"] = "no-store"
        if environment == "production":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    with app.app_context():
        initialize_database()

    def legal_page(title, intro, sections):
        content = "\n".join(
            f"<section><h2>{heading}</h2>{body}</section>" for heading, body in sections
        )
        return render_template_string(
            """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>{{ title }}</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 0; background: #f5f7f4; color: #1d2d29; }
                .wrap { max-width: 900px; margin: 0 auto; padding: 48px 22px 72px; }
                .card { background: #fff; border: 1px solid #dfe9e2; border-radius: 12px; box-shadow: 0 12px 26px rgba(13, 35, 30, 0.06); padding: 28px 30px; }
                h1 { margin-top: 0; font-size: clamp(2rem, 3vw, 2.7rem); }
                p, li { color: #3b4d46; line-height: 1.7; }
                h2 { margin-top: 28px; color: #163d34; }
                ul { padding-left: 20px; }
                a { color: #0d5f51; }
                .back { display: inline-block; margin-bottom: 20px; color: #0d5f51; text-decoration: none; font-weight: 600; }
              </style>
            </head>
            <body>
              <div class="wrap">
                <a class="back" href="/">← Back to Morrow</a>
                <div class="card">
                  <h1>{{ title }}</h1>
                  <p>{{ intro }}</p>
                  {{ content | safe }}
                </div>
              </div>
            </body>
            </html>
            """,
            title=title,
            intro=intro,
            content=content,
        )

    @app.get("/")
    def homepage():
        for file_name in ("index.html", "web.html", "welcome-preview.html"):
            candidate = BASE_DIR / file_name
            if candidate.exists():
                return send_from_directory(BASE_DIR, file_name)
        return "Morrow homepage not found.", 404

    @app.get("/index.html")
    def homepage_index():
        return homepage()

    @app.get("/about")
    def about_page():
        return render_template_string(
                        """
                        <!doctype html>
                        <html lang="en">
                        <head>
                            <meta charset="utf-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1">
                            <meta name="theme-color" content="#163d35">
                            <title>About Morrow | Home Services in Junagadh</title>
                            <meta name="description" content="Learn about Morrow Home Services, the request and quote process, and professional applications in Junagadh.">
                            <link rel="preconnect" href="https://fonts.googleapis.com">
                            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
                            <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
                            <style>
                                :root { --forest: #163d35; --deep: #0d2b26; --leaf: #d8ee9b; --coral: #e77a60; --paper: #f6f7f2; --ink: #172b27; --muted: #687872; --display: "Manrope", "Segoe UI", sans-serif; --body: "DM Sans", "Segoe UI", sans-serif; color: var(--ink); background: var(--paper); font-family: var(--body); }
                                * { box-sizing: border-box; }
                                body { min-width: 320px; margin: 0; }
                                a { color: inherit; text-decoration: none; }
                                img { display: block; width: 100%; }
                                .about-shell { width: min(1160px, calc(100% - 48px)); margin-inline: auto; }
                                .about-header { position: sticky; z-index: 5; top: 0; border-bottom: 1px solid rgb(22 61 53 / 9%); background: rgb(246 247 242 / 94%); backdrop-filter: blur(12px); }
                                .about-header-inner { min-height: 72px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
                                .about-brand { display: inline-flex; align-items: center; gap: 10px; font: 800 19px var(--display); }
                                .about-brand-mark { width: 30px; height: 30px; position: relative; display: grid; place-items: center; border-radius: 8px 8px 8px 2px; background: var(--leaf); transform: rotate(-4deg); }
                                .about-brand-mark::before, .about-brand-mark::after { position: absolute; content: ""; background: var(--forest); border-radius: 4px; }
                                .about-brand-mark::before { width: 14px; height: 4px; transform: rotate(-42deg); }
                                .about-brand-mark::after { width: 4px; height: 14px; transform: translate(4px,-2px) rotate(-42deg); }
                                .about-nav { display: flex; align-items: center; gap: 24px; color: #465852; font-size: 12px; font-weight: 700; }
                                .about-nav a:hover, .about-footer a:hover { color: var(--coral); }
                                .about-button { min-height: 40px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 0 14px; border-radius: 4px; color: white; background: var(--forest); font-size: 11px; font-weight: 700; }
                                .about-button:hover { background: var(--deep); }
                                .about-hero { display: grid; grid-template-columns: .9fr 1.1fr; align-items: center; gap: 56px; padding-block: 56px 62px; }
                                .about-eyebrow { display: inline-flex; align-items: center; gap: 9px; color: #52675c; font-size: 10px; font-weight: 700; letter-spacing: 1.4px; text-transform: uppercase; }
                                .about-eyebrow::before { width: 21px; height: 2px; content: ""; background: var(--coral); }
                                .about-hero h1 { max-width: 520px; margin: 18px 0; font: 600 50px/1.05 var(--display); }
                                .about-hero h1 em { color: var(--forest); font-family: Georgia, "Times New Roman", serif; font-weight: 400; }
                                .about-hero p { max-width: 455px; margin: 0 0 22px; color: var(--muted); font-size: 15px; line-height: 1.75; }
                                .about-hero-image { min-height: 410px; position: relative; overflow: hidden; border-radius: 5px; background: #d5ddd4; }
                                .about-hero-image img { height: 410px; object-fit: cover; }
                                .about-image-caption { position: absolute; right: 14px; bottom: 14px; left: 14px; padding: 12px 14px; border: 1px solid rgb(255 255 255 / 40%); border-radius: 3px; color: white; background: rgb(13 43 38 / 82%); font-size: 11px; }
                                .about-facts { color: white; background: var(--forest); }
                                .about-facts-inner { min-height: 100px; display: grid; grid-template-columns: repeat(3, 1fr); align-items: center; gap: 20px; }
                                .about-fact { display: flex; align-items: center; justify-content: center; gap: 11px; }
                                .about-fact strong { color: var(--leaf); font: 700 18px var(--display); }
                                .about-fact span { max-width: 150px; color: #d4e1da; font-size: 11px; line-height: 1.4; }
                                .about-section { padding-block: 78px; }
                                .about-section-heading { max-width: 680px; margin-bottom: 28px; }
                                .about-section h2 { margin: 12px 0; font: 600 35px/1.15 var(--display); }
                                .about-section-heading p { max-width: 590px; color: var(--muted); font-size: 14px; line-height: 1.75; }
                                .about-pillars { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
                                .about-pillar { min-height: 176px; padding: 20px; border: 1px solid #dfe6df; border-radius: 4px; background: white; }
                                .about-pillar span { color: var(--coral); font-size: 10px; font-weight: 700; letter-spacing: 1px; }
                                .about-pillar h3 { margin: 23px 0 8px; font: 700 16px var(--display); }
                                .about-pillar p { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.65; }
                                .about-process { color: white; background: var(--deep); }
                                .about-process .about-eyebrow { color: #c7d6ce; }
                                .about-process .about-section-heading p { color: #c5d4cb; }
                                .about-steps { display: grid; grid-template-columns: repeat(3, 1fr); gap: 13px; }
                                .about-step { min-height: 165px; padding: 17px; border: 1px solid rgb(255 255 255 / 18%); border-radius: 4px; background: rgb(255 255 255 / 4%); }
                                .about-step b { display: inline-grid; width: 28px; height: 28px; place-items: center; border-radius: 50%; color: var(--forest); background: var(--leaf); font: 700 11px var(--display); }
                                .about-step h3 { margin: 20px 0 8px; font: 700 14px var(--display); }
                                .about-step p { margin: 0; color: #c5d4cb; font-size: 11px; line-height: 1.65; }
                                .about-note { margin-top: 17px; color: #d8e4dc; font-size: 11px; line-height: 1.6; }
                                .about-join { display: flex; align-items: center; justify-content: space-between; gap: 24px; padding: 28px; border-left: 4px solid var(--coral); background: #eef2eb; }
                                .about-join h2 { margin: 0 0 7px; font: 600 25px var(--display); }
                                .about-join p { max-width: 610px; margin: 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
                                .about-footer { padding-block: 24px; color: #d5e0d9; background: #0b2722; }
                                .about-footer-inner { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
                                .about-footer p { margin: 0; font-size: 10px; }
                                .about-footer nav { display: flex; gap: 17px; font-size: 10px; }
                                @media (max-width: 760px) {
                                    .about-shell { width: min(100% - 32px, 560px); }
                                    .about-header-inner { min-height: 62px; }
                                    .about-nav { gap: 12px; font-size: 10px; }
                                    .about-nav a:nth-child(2) { display: none; }
                                    .about-hero { grid-template-columns: 1fr; gap: 25px; padding-block: 37px 44px; }
                                    .about-hero h1 { font-size: 39px; }
                                    .about-hero p { font-size: 13px; }
                                    .about-hero-image, .about-hero-image img { min-height: 290px; height: 290px; }
                                    .about-facts-inner { grid-template-columns: 1fr; gap: 12px; padding-block: 17px; }
                                    .about-fact { justify-content: flex-start; }
                                    .about-section { padding-block: 56px; }
                                    .about-section h2 { font-size: 29px; }
                                    .about-pillars, .about-steps { grid-template-columns: 1fr; }
                                    .about-pillar, .about-step { min-height: 0; }
                                    .about-pillar h3 { margin-top: 15px; }
                                    .about-join, .about-footer-inner { align-items: flex-start; flex-direction: column; }
                                    .about-join { padding: 20px; }
                                    .about-footer nav { flex-wrap: wrap; }
                                }
                            </style>
                        </head>
                        <body>
                            <header class="about-header">
                                <div class="about-shell about-header-inner">
                                    <a class="about-brand" href="/" aria-label="Morrow home"><span class="about-brand-mark" aria-hidden="true"></span><span>Morrow</span></a>
                                    <nav class="about-nav" aria-label="About navigation">
                                        <a href="/#services">Services</a>
                                        <a href="/#join">For professionals</a>
                                        <a href="/#help">Contact</a>
                                    </nav>
                                    <a class="about-button" href="/">Back to website <span aria-hidden="true">→</span></a>
                                </div>
                            </header>
                            <main>
                                <section class="about-shell about-hero" aria-labelledby="aboutTitle">
                                    <div>
                                        <span class="about-eyebrow">About Morrow</span>
                                        <h1 id="aboutTitle">Good help.<br><em>Right at home.</em></h1>
                                        <p>Morrow is a home-services starting point for people in Junagadh. Find help with repairs, cleaning, improvements, and everyday upkeep, then send a request for the team to review.</p>
                                        <a class="about-button" href="/#services">Explore services <span aria-hidden="true">→</span></a>
                                    </div>
                                    <div class="about-hero-image">
                                        <img src="https://images.unsplash.com/photo-1621905251918-48416bd8575a?auto=format&fit=crop&w=1200&q=86" alt="A home service professional working on a home electrical installation" loading="lazy">
                                        <div class="about-image-caption">Home care, coordinated close to home.</div>
                                    </div>
                                </section>

                                <section class="about-facts" aria-label="Morrow at a glance">
                                    <div class="about-shell about-facts-inner">
                                        <div class="about-fact"><strong>12</strong><span>service categories to explore</span></div>
                                        <div class="about-fact"><strong>Junagadh</strong><span>our current service area</span></div>
                                        <div class="about-fact"><strong>Clear quotes</strong><span>final price confirmed before payment</span></div>
                                    </div>
                                </section>

                                <section class="about-shell about-section" aria-labelledby="aboutApproachTitle">
                                    <div class="about-section-heading">
                                        <span class="about-eyebrow">A practical approach</span>
                                        <h2 id="aboutApproachTitle">Home care should start with a clear next step.</h2>
                                        <p>Morrow brings common home-service requests into one place. Customers choose a service, share the details, and wait for confirmation instead of treating a request as an already scheduled appointment.</p>
                                    </div>
                                    <div class="about-pillars">
                                        <article class="about-pillar"><span>01 · REPAIRS</span><h3>Everyday fixes</h3><p>Plumbing, electrical help, appliance repairs, heating and cooling, and handyman visits.</p></article>
                                        <article class="about-pillar"><span>02 · HOME CARE</span><h3>A fresher space</h3><p>Home and deep cleaning, window washing, painting, and furniture assembly.</p></article>
                                        <article class="about-pillar"><span>03 · IMPROVEMENTS</span><h3>Room to improve</h3><p>Smart home setup and lawn or garden care, alongside other home upkeep requests.</p></article>
                                    </div>
                                </section>

                                <section class="about-process about-section" aria-labelledby="aboutProcessTitle">
                                    <div class="about-shell">
                                        <div class="about-section-heading">
                                            <span class="about-eyebrow">How a request moves</span>
                                            <h2 id="aboutProcessTitle">Request first. Confirm together.</h2>
                                            <p>The steps are designed to keep the requested work, timing, and final price clear before a visit is arranged.</p>
                                        </div>
                                        <div class="about-steps">
                                            <article class="about-step"><b>1</b><h3>Choose and describe</h3><p>Select a service, provide the address, and send a preferred date and time window.</p></article>
                                            <article class="about-step"><b>2</b><h3>Wait for review</h3><p>Morrow reviews availability and confirms the service details and final quote with you.</p></article>
                                            <article class="about-step"><b>3</b><h3>Pay the confirmed quote</h3><p>When online checkout is enabled, pay the full confirmed amount through Razorpay before service begins. The initial card prices are estimates, not final quotes.</p></article>
                                        </div>
                                        <p class="about-note">Checkout is available only after Morrow configures its payment account and confirms your booking. Never send money directly to an individual claiming to be an agent.</p>
                                    </div>
                                </section>

                                <section class="about-shell about-section" aria-labelledby="aboutProfessionalsTitle">
                                    <div class="about-join">
                                        <div><h2 id="aboutProfessionalsTitle">Are you a home-service professional?</h2><p>Apply with your experience, service area, and skills. Morrow reviews applications; applying does not guarantee approval or paid work.</p></div>
                                        <a class="about-button" href="/#join">Apply to Morrow <span aria-hidden="true">→</span></a>
                                    </div>
                                </section>
                            </main>
                            <footer class="about-footer">
                                <div class="about-shell about-footer-inner">
                                    <p>Good help. Right at home. · Junagadh, Gujarat</p>
                                    <nav aria-label="Legal and contact links"><a href="mailto:shyamghoniya@gmail.com">Email Morrow</a><a href="/terms">Terms</a><a href="/privacy">Privacy</a></nav>
                                </div>
                            </footer>
                        </body>
                        </html>
                        """
                )

    @app.get("/terms")
    def terms_page():
        return legal_page(
            "Terms & Conditions",
            "These website terms govern how customers use Morrow Home Services and request home maintenance support.",
            [
                ("1. Services", "<p>Morrow provides a platform for connecting customers with local home service providers. All service requests are subject to availability, confirmation, and scheduling approval by the service team.</p>"),
                ("2. Booking responsibility", "<p>Customers are responsible for providing accurate addresses, preferred dates, and contact details. We may reject or postpone requests if information is incomplete or incorrect.</p>"),
                ("3. Quotes and payment", "<p>Morrow reviews each request and sets a final quote before payment. When online checkout is enabled, the full confirmed amount is paid through the Razorpay checkout opened from the customer account before service begins. Do not send money directly to a service professional. Keep the payment receipt and contact Morrow about cancellation or refund questions.</p>"),
                ("4. Service professional applications", "<p>Submitting an application does not make someone a Morrow agent or guarantee work. Applications are reviewed separately, and Morrow contacts applicants about any next steps.</p>"),
                ("5. Acceptance of use", "<p>By using this website, you agree to use it for lawful and honest purposes. You agree not to misuse the booking system or submit false or abusive requests.</p>"),
                ("6. Limitation of liability", "<p>Morrow is a service coordination platform. We are not directly responsible for provider workmanship beyond the coordination and booking process unless stated otherwise in writing.</p>"),
            ],
        )

    @app.get("/privacy")
    def privacy_page():
        return legal_page(
            "Privacy Policy",
            "We respect your privacy and only use your information to run the Morrow website and service experience safely.",
            [
                ("Information we collect", "<p>We may collect customer names, email addresses, phone numbers, service addresses, booking details, and account login information. People applying as service professionals may also submit their contact details, service area, experience, and skills.</p>"),
                ("How we use it", "<p>We use this information to manage customer accounts and bookings, review service professional applications, coordinate services, and respond to support requests.</p>"),
                ("Payments", "<p>When Razorpay checkout is enabled, Razorpay processes payment details. Morrow stores payment order references and payment status, not full card or UPI credentials.</p>"),
                ("Data security", "<p>Passwords are stored as salted hashes. Session cookies are signed, HttpOnly, and same-site. Access to application and booking records is restricted to the owner dashboard.</p>"),
                ("Sharing", "<p>We do not sell personal data. Information is shared with service professionals only as needed to coordinate a requested service. Razorpay processes online payments under its own privacy terms.</p>"),
                ("Your rights", "<p>You may contact Morrow to ask about, update, or request deletion of account or application information, subject to records we must retain.</p>"),
            ],
        )

    @app.get("/cookies")
    def cookies_page():
        return legal_page(
            "Cookie Policy",
            "Cookies help us remember your browsing session, keep your account secure, and improve your experience on the Morrow website.",
            [
                ("What are cookies?", "<p>Cookies are small files stored on your browser to remember user preferences, session information, and website activity needed for a smoother experience.</p>"),
                ("What we use cookies for", "<ul><li>Keep you logged in during your browsing session.</li><li>Protect login and form security.</li><li>Remember your preferences on the site.</li></ul>"),
                ("Managing cookies", "<p>You can manage or disable cookies from your browser settings. Please note that some website features may not work correctly if cookies are disabled.</p>"),
            ],
        )

    @app.get("/admin")
    def admin_dashboard():
        if not session.get("admin_authenticated"):
            return render_template_string(
                """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>Morrow Admin Access</title>
                  <style>
                    body { margin: 0; font-family: Arial, sans-serif; background: #f4f7f4; color: #1d2d29; }
                    .wrap { max-width: 460px; margin: 80px auto; padding: 24px; }
                    .card { background: #fff; border: 1px solid #dfe8e1; border-radius: 14px; padding: 28px 26px; box-shadow: 0 10px 22px rgba(15, 37, 31, 0.06); }
                    h1 { margin-top: 0; font-size: 1.9rem; }
                    label { display: block; margin: 18px 0 8px; font-weight: 700; }
                    input { width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1px solid #cdd8d1; border-radius: 10px; font-size: 1rem; }
                    button { width: 100%; margin-top: 18px; background: #0d5f51; color: white; border: none; border-radius: 10px; padding: 12px 16px; cursor: pointer; font-weight: 700; }
                    .error { color: #9f2b2b; margin-top: 12px; font-weight: 700; }
                    .back { display: inline-block; margin-bottom: 18px; color: #0d5f51; text-decoration: none; font-weight: 700; }
                  </style>
                </head>
                <body>
                  <div class="wrap">
                    <a class="back" href="/">← Back to website</a>
                    <div class="card">
                      <h1>Admin access</h1>
                      <p>Enter admin password to open the owner dashboard.</p>
                      <form method="post" action="/admin/login">
                                                <input type="hidden" name="csrf_token" value="{{ admin_csrf_token }}">
                        <label for="password">Password</label>
                        <input id="password" type="password" name="password" autocomplete="current-password" required>
                        <button type="submit">Open dashboard</button>
                        {% if error %}
                          <div class="error">{{ error }}</div>
                        {% endif %}
                      </form>
                    </div>
                  </div>
                </body>
                </html>
                """,
                error=request.args.get("error", "") or (
                    "Set MORROW_ADMIN_SECRET in the server environment to enable the owner dashboard."
                    if not app.config["ADMIN_SECRET"] else ""
                ),
                admin_csrf_token=csrf_token(),
            )

        messages = get_db().execute(
            "SELECT id, name, email, message, created_at FROM contact_messages ORDER BY id DESC LIMIT 20"
        ).fetchall()
        bookings = get_db().execute(
            """SELECT bookings.id, users.name, users.email, bookings.service,
                      bookings.preferred_date, bookings.preferred_window, bookings.status,
                      bookings.quote_amount_paise, bookings.quote_before_discount_paise,
                      bookings.discount_amount_paise, bookings.payment_status
               FROM bookings JOIN users ON users.id = bookings.user_id
               ORDER BY bookings.id DESC LIMIT 20"""
        ).fetchall()
        agent_rows = get_db().execute(
            """SELECT id, name, email, phone, service_area, services_json, experience, status, created_at
               FROM agent_applications ORDER BY id DESC LIMIT 50"""
        ).fetchall()
        agent_applications = [
            {**dict(row), "services": ", ".join(json.loads(row["services_json"]))}
            for row in agent_rows
        ]

        return render_template_string(
            """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Morrow Admin</title>
              <style>
                body { margin: 0; background: #f4f7f4; font-family: Arial, sans-serif; color: #1a2d28; }
                .wrap { max-width: 1200px; margin: 0 auto; padding: 32px 20px 60px; }
                h1 { margin-bottom: 8px; }
                .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }
                .card { background: #fff; border: 1px solid #dfe8e1; border-radius: 12px; padding: 18px; box-shadow: 0 8px 20px rgba(15, 37, 31, 0.04); }
                table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; }
                th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #ecf1ed; font-size: 13px; vertical-align: top; }
                th { background: #eaf0eb; }
                .muted { color: #5e7068; }
                .badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; background: #e3f3ea; color: #1c5b4f; }
              </style>
            </head>
            <body>
              <div class="wrap">
                                <form method="post" action="/admin/leave" style="margin:0 0 18px;">
                                    <input type="hidden" name="csrf_token" value="{{ admin_csrf_token }}">
                                    <button type="submit" style="padding:0;border:0;color:#0d5f51;background:transparent;font-weight:700;text-decoration:underline;cursor:pointer;">Log out of dashboard</button>
                                </form>
                <h1>Morrow owner dashboard</h1>
                <p class="muted">Review customer requests, quotes, and service professional applications.</p>
                {% if admin_notice %}<p class="muted" role="status">{{ admin_notice }}</p>{% endif %}

                <div class="summary">
                  <div class="card"><strong>Support messages</strong><div>{{ messages|length }}</div></div>
                  <div class="card"><strong>Service requests</strong><div>{{ bookings|length }}</div></div>
                  <div class="card"><strong>Agent applications</strong><div>{{ agent_applications|length }}</div></div>
                </div>

                                <div class="card">
                                    <h2>Service professional applications</h2>
                                    {% if agent_applications %}
                                        <table>
                                            <thead><tr><th>ID</th><th>Name</th><th>Contact</th><th>Area</th><th>Services</th><th>Experience</th><th>Received</th><th>Status</th></tr></thead>
                                            <tbody>
                                                {% for applicant in agent_applications %}
                                                    <tr>
                                                        <td>{{ applicant['id'] }}</td>
                                                        <td>{{ applicant['name'] }}</td>
                                                        <td><a href="mailto:{{ applicant['email'] }}">{{ applicant['email'] }}</a><br>{{ applicant['phone'] }}</td>
                                                        <td>{{ applicant['service_area'] }}</td>
                                                        <td>{{ applicant['services'] }}</td>
                                                        <td>{{ applicant['experience'] }}</td>
                                                        <td>{{ applicant['created_at'] }}</td>
                                                        <td><span class="badge">{{ applicant['status'] }}</span></td>
                                                    </tr>
                                                {% endfor %}
                                            </tbody>
                                        </table>
                                    {% else %}
                                        <p>No professional applications yet.</p>
                                    {% endif %}
                                </div>

                <div class="card">
                  <h2>Recent support messages</h2>
                  {% if messages %}
                    <table>
                      <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Message</th><th>Date</th></tr></thead>
                      <tbody>
                        {% for message in messages %}
                          <tr>
                            <td>{{ message['id'] }}</td>
                            <td>{{ message['name'] }}</td>
                            <td>{{ message['email'] }}</td>
                            <td>{{ message['message'] }}</td>
                            <td>{{ message['created_at'] }}</td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  {% else %}
                    <p>No support messages yet.</p>
                  {% endif %}
                </div>

                <div class="card" style="margin-top: 24px;">
                  <h2>Recent service requests</h2>
                  {% if bookings %}
                    <table>
                      <thead><tr><th>ID</th><th>Customer</th><th>Email</th><th>Service</th><th>Date</th><th>Window</th><th>Status</th><th>Base quote</th><th>First-request savings</th><th>Amount due</th><th>Payment</th><th>Accept request & set base quote (₹)</th></tr></thead>
                      <tbody>
                        {% for booking in bookings %}
                          <tr>
                            <td>{{ booking['id'] }}</td>
                            <td>{{ booking['name'] }}</td>
                            <td>{{ booking['email'] }}</td>
                            <td>{{ booking['service'] }}</td>
                            <td>{{ booking['preferred_date'] }}</td>
                            <td>{{ booking['preferred_window'] }}</td>
                            <td><span class="badge">{{ booking['status'] }}</span></td>
                                                        <td>{% if booking['quote_before_discount_paise'] %}₹{{ '%.2f'|format(booking['quote_before_discount_paise'] / 100) }}{% else %}Not set{% endif %}</td>
                                                        <td>{% if booking['discount_amount_paise'] %}{{ first_booking_discount_percent }}% · −₹{{ '%.2f'|format(booking['discount_amount_paise'] / 100) }}{% else %}—{% endif %}</td>
                                                        <td>{% if booking['quote_amount_paise'] %}₹{{ '%.2f'|format(booking['quote_amount_paise'] / 100) }}{% else %}Not set{% endif %}</td>
                                                        <td>{{ booking['payment_status'] }}</td>
                                                        <td>
                                                            <form method="post" action="/admin/bookings/{{ booking['id'] }}/quote" style="display:flex;gap:6px;min-width:160px;">
                                                                <input type="hidden" name="csrf_token" value="{{ admin_csrf_token }}">
                                                                <input type="number" name="quote_rupees" min="1" max="1000000" step="1" value="{% if booking['quote_before_discount_paise'] %}{{ booking['quote_before_discount_paise'] // 100 }}{% endif %}" placeholder="Amount" required style="min-width:84px;width:90px;padding:7px;border:1px solid #cdd8d1;border-radius:4px;">
                                                                <button type="submit" style="padding:7px 9px;border:0;border-radius:4px;background:#d8ee9b;color:#163d35;font-weight:700;cursor:pointer;">Accept & notify</button>
                                                            </form>
                                                        </td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  {% else %}
                    <p>No booking requests yet.</p>
                  {% endif %}
                </div>
              </div>
            </body>
            </html>
            """,
            messages=messages,
            bookings=bookings,
            agent_applications=agent_applications,
            admin_csrf_token=csrf_token(),
            first_booking_discount_percent=FIRST_BOOKING_DISCOUNT_PERCENT,
            admin_notice=session.pop("admin_notice", None),
        )

    @app.post("/admin/leave")
    def leave_admin_dashboard():
        supplied_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")
        if not supplied_token or not expected_token or not hmac.compare_digest(supplied_token, expected_token):
            return error_response("Refresh the dashboard and try again.", 400)
        session.clear()
        return redirect("/")

    @app.post("/admin/bookings/<int:booking_id>/quote")
    def set_booking_quote(booking_id):
        if not session.get("admin_authenticated"):
            return redirect("/admin")

        supplied_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")
        if not supplied_token or not expected_token or not hmac.compare_digest(supplied_token, expected_token):
            return error_response("Refresh the dashboard and try again.", 400)

        try:
            quote_rupees = int(request.form.get("quote_rupees", ""))
        except ValueError:
            return error_response("Enter a valid quote in rupees.", 400)
        if not 1 <= quote_rupees <= 1_000_000:
            return error_response("The quote must be between ₹1 and ₹10,00,000.", 400)

        database = get_db()
        booking = database.execute(
            """SELECT id, user_id, service, phone, preferred_date, preferred_window, status,
                      payment_status
               FROM bookings WHERE id = ?""",
            (booking_id,),
        ).fetchone()
        if booking is None:
            return error_response("Booking not found.", 404)
        if booking["payment_status"] == "paid":
            return error_response("A paid booking cannot be repriced.", 409)
        is_new_acceptance = booking["status"] == "pending"

        first_booking_id = database.execute(
            "SELECT MIN(id) FROM bookings WHERE user_id = ?",
            (booking["user_id"],),
        ).fetchone()[0]
        quote_before_discount_paise = quote_rupees * 100
        discount_amount_paise = (
            quote_before_discount_paise * FIRST_BOOKING_DISCOUNT_PERCENT // 100
            if booking_id == first_booking_id
            else 0
        )
        quote_amount_paise = quote_before_discount_paise - discount_amount_paise

        database.execute(
            """UPDATE bookings
               SET quote_amount_paise = ?, quote_before_discount_paise = ?, discount_amount_paise = ?,
                   status = 'awaiting_payment', payment_status = 'unpaid',
                   razorpay_order_id = NULL, payment_id = NULL
               WHERE id = ?""",
            (quote_amount_paise, quote_before_discount_paise, discount_amount_paise, booking_id),
        )
        database.commit()
        if is_new_acceptance:
            accepted_booking = dict(booking)
            sms_sent = send_booking_acceptance_sms(accepted_booking, quote_amount_paise)
            session["admin_notice"] = (
                "Request accepted. SMS confirmation sent to the customer."
                if sms_sent
                else "Request accepted and payment enabled. SMS was not sent; configure Twilio and the HTTPS public URL to enable phone notifications."
            )
        else:
            session["admin_notice"] = "Quote updated. The customer can pay from their account."
        return redirect("/admin")

    @app.post("/admin/login")
    @limiter.limit("5 per minute")
    def admin_login():
        if not app.config["ADMIN_SECRET"]:
            return error_response("The owner dashboard is not configured.", 503)
        supplied_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")
        if not supplied_token or not expected_token or not hmac.compare_digest(supplied_token, expected_token):
            return error_response("Refresh the page and try again.", 400)

        submitted_password = request.form.get("password", "")
        if hmac.compare_digest(submitted_password, app.config["ADMIN_SECRET"]):
            session.clear()
            session["admin_authenticated"] = True
            csrf_token()
            return redirect("/admin")
        return redirect("/admin?error=Incorrect+admin+password")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/csrf")
    def get_csrf_token():
        return jsonify(csrf_token=csrf_token())

    @app.get("/api/session")
    def get_session():
        user = current_user()
        if user is None:
            return jsonify(user=None)
        return jsonify(user=serialize_user(user))

    @app.get("/api/payments/config")
    def get_payment_config():
        return jsonify(
            available=bool(app.config["RAZORPAY_KEY_ID"] and app.config["RAZORPAY_KEY_SECRET"])
        )

    @app.get("/api/google/config")
    def get_google_config():
        return jsonify(available=google_oauth is not None)

    @app.get("/auth/google/connect")
    def connect_google():
        user = current_user()
        if user is None:
            return redirect("/?google=login_required")
        if google_oauth is None:
            return redirect("/?google=unavailable")
        nonce = secrets.token_urlsafe(24)
        return google_oauth.authorize_redirect(
            url_for("google_connect_callback", _external=True),
            nonce=nonce,
        )

    @app.get("/auth/google/callback")
    def google_connect_callback():
        user = current_user()
        if user is None:
            return redirect("/?google=login_required")
        if google_oauth is None:
            return redirect("/?google=unavailable")

        try:
            token = google_oauth.authorize_access_token()
            identity = token.get("userinfo")
        except Exception:
            app.logger.exception("Google account linking failed for user %s", user["id"])
            return redirect("/?google=error")

        if (
            not isinstance(identity, dict)
            or not isinstance(identity.get("sub"), str)
            or not isinstance(identity.get("email"), str)
            or identity.get("email_verified") is not True
        ):
            return redirect("/?google=error")

        database = get_db()
        existing_link = database.execute(
            "SELECT id FROM users WHERE google_sub = ?",
            (identity["sub"],),
        ).fetchone()
        if existing_link is not None and existing_link["id"] != user["id"]:
            return redirect("/?google=already_linked")
        if user["google_sub"] and user["google_sub"] != identity["sub"]:
            return redirect("/?google=already_linked")

        database.execute(
            "UPDATE users SET google_email = ?, google_sub = ? WHERE id = ?",
            (identity["email"].lower(), identity["sub"], user["id"]),
        )
        database.commit()
        return redirect("/?google=connected")

    @app.post("/api/bookings/<int:booking_id>/payment/order")
    @limiter.limit("5 per minute")
    def create_payment_order(booking_id):
        user = current_user()
        if user is None:
            return error_response("Log in to pay for this service request.", 401)
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        key_id = app.config["RAZORPAY_KEY_ID"].strip()
        key_secret = app.config["RAZORPAY_KEY_SECRET"].strip()
        if not key_id or not key_secret:
            return error_response("Online payments are not configured yet. Contact Morrow before sending money.", 503)

        booking = get_db().execute(
            """SELECT id, service, phone, status, quote_amount_paise, payment_status
               FROM bookings WHERE id = ? AND user_id = ?""",
            (booking_id, user["id"]),
        ).fetchone()
        if booking is None:
            return error_response("Service request not found.", 404)
        if booking["payment_status"] == "paid":
            return error_response("This service request is already paid.", 409)
        if booking["status"] != "awaiting_payment" or not booking["quote_amount_paise"]:
            return error_response("Wait for Morrow to confirm your final quote before paying.", 409)

        order_payload = {
            "amount": booking["quote_amount_paise"],
            "currency": "INR",
            "receipt": f"morrow-{booking_id}-{secrets.token_hex(5)}",
            "notes": {"booking_id": str(booking_id)},
        }
        authorization = base64.b64encode(f"{key_id}:{key_secret}".encode()).decode("ascii")
        provider_request = Request(
            "https://api.razorpay.com/v1/orders",
            data=json.dumps(order_payload).encode(),
            headers={"Authorization": f"Basic {authorization}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(provider_request, timeout=15) as provider_response:
                order = json.loads(provider_response.read().decode())
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.exception("Razorpay order creation failed for booking %s", booking_id)
            return error_response("Could not start payment. Please try again or contact Morrow.", 502)

        order_id = order.get("id")
        if not isinstance(order_id, str) or not order_id.startswith("order_"):
            return error_response("Payment provider returned an invalid order.", 502)

        get_db().execute(
            "UPDATE bookings SET razorpay_order_id = ? WHERE id = ? AND user_id = ?",
            (order_id, booking_id, user["id"]),
        )
        get_db().commit()
        return jsonify(
            key_id=key_id,
            order_id=order_id,
            amount=booking["quote_amount_paise"],
            currency="INR",
            service=booking["service"],
            prefill={"name": user["name"], "email": user["email"], "contact": booking["phone"]},
        )

    @app.post("/api/bookings/<int:booking_id>/payment/verify")
    @limiter.limit("10 per minute")
    def verify_payment(booking_id):
        user = current_user()
        if user is None:
            return error_response("Log in to verify this payment.", 401)
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        key_id = app.config["RAZORPAY_KEY_ID"].strip()
        key_secret = app.config["RAZORPAY_KEY_SECRET"].strip()
        if not key_id or not key_secret:
            return error_response("Online payments are not configured yet.", 503)

        payload = json_payload()
        order_id = clean_text(payload.get("razorpay_order_id"), 100)
        payment_id = clean_text(payload.get("razorpay_payment_id"), 100)
        signature = clean_text(payload.get("razorpay_signature"), 128)
        if not re.fullmatch(r"order_[A-Za-z0-9]+", order_id) or not re.fullmatch(r"pay_[A-Za-z0-9]+", payment_id):
            return error_response("Payment details are invalid.", 400)

        booking = get_db().execute(
            """SELECT id, quote_amount_paise, razorpay_order_id, payment_id, payment_status
               FROM bookings WHERE id = ? AND user_id = ?""",
            (booking_id, user["id"]),
        ).fetchone()
        if booking is None:
            return error_response("Service request not found.", 404)
        if booking["payment_status"] == "paid" and booking["payment_id"] == payment_id:
            return jsonify(success=True, payment_status="paid")
        if not booking["razorpay_order_id"] or not hmac.compare_digest(order_id, booking["razorpay_order_id"]):
            return error_response("This payment does not match the current service quote.", 400)

        expected_signature = hmac.new(
            key_secret.encode(),
            f"{order_id}|{payment_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if not signature or not hmac.compare_digest(signature, expected_signature):
            return error_response("Payment signature could not be verified.", 400)

        authorization = base64.b64encode(f"{key_id}:{key_secret}".encode()).decode("ascii")
        provider_request = Request(
            f"https://api.razorpay.com/v1/payments/{payment_id}",
            headers={"Authorization": f"Basic {authorization}"},
            method="GET",
        )
        try:
            with urlopen(provider_request, timeout=15) as provider_response:
                payment = json.loads(provider_response.read().decode())
        except (HTTPError, URLError, TimeoutError, ValueError):
            app.logger.exception("Razorpay payment verification failed for booking %s", booking_id)
            return error_response("Could not confirm payment with Razorpay. Please contact Morrow before retrying.", 502)

        if (
            payment.get("order_id") != order_id
            or payment.get("amount") != booking["quote_amount_paise"]
            or payment.get("currency") != "INR"
            or payment.get("status") != "captured"
        ):
            return error_response("Payment is not captured yet. Contact Morrow before trying again.", 409)

        get_db().execute(
            """UPDATE bookings SET payment_id = ?, payment_status = 'paid', status = 'paid'
               WHERE id = ? AND user_id = ?""",
            (payment_id, booking_id, user["id"]),
        )
        get_db().commit()
        return jsonify(success=True, payment_status="paid")

    @app.post("/api/register")
    @limiter.limit("5 per minute")
    def register():
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        payload = json_payload()
        name = clean_text(payload.get("name"), 100)
        email = clean_text(payload.get("email"), 254).lower()
        password = payload.get("password")
        accepted_terms = payload.get("accept_terms") is True
        if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            return error_response("Enter your name and a valid email address.", 400)
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            return error_response("Your password must be between 8 and 128 characters.", 400)
        if not accepted_terms:
            return error_response("Please accept the terms to create an account.", 400)

        database = get_db()
        try:
            cursor = database.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password)),
            )
            database.commit()
        except sqlite3.IntegrityError:
            return error_response("An account with that email already exists. Try logging in.", 409)

        session.clear()
        session["user_id"] = cursor.lastrowid
        registered_user = get_db().execute(
            "SELECT id, name, email, google_email, google_sub FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        return jsonify(
            user=serialize_user(registered_user),
            csrf_token=csrf_token(),
        ), 201

    @app.post("/api/login")
    @limiter.limit("5 per minute")
    def login():
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        payload = json_payload()
        email = clean_text(payload.get("email"), 254).lower()
        password = payload.get("password")
        user = get_db().execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if user is None or not isinstance(password, str) or not check_password_hash(user["password_hash"], password):
            return error_response("Email or password is incorrect.", 401)

        session.clear()
        session["user_id"] = user["id"]
        refreshed_user = get_db().execute(
            "SELECT id, name, email, google_email, google_sub FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        return jsonify(
            user=serialize_user(refreshed_user),
            csrf_token=csrf_token(),
        )

    @app.post("/api/contact")
    @limiter.limit("10 per hour")
    def contact():
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        payload = json_payload()
        name = clean_text(payload.get("name"), 100)
        email = clean_text(payload.get("email"), 254).lower()
        message = clean_text(payload.get("message"), 2000)
        if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not message:
            return error_response("Enter your name, a valid email address, and a message.", 400)

        get_db().execute(
            "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)",
            (name, email, message),
        )
        get_db().commit()
        return jsonify(success=True, message="Message sent."), 201

    @app.post("/api/agent-applications")
    @limiter.limit("5 per minute")
    def create_agent_application():
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        payload = json_payload()
        name = clean_text(payload.get("name"), 100)
        email = clean_text(payload.get("email"), 254).lower()
        phone = clean_text(payload.get("phone"), 20)
        normalized_phone = re.sub(r"[\s-]", "", phone)
        service_area = clean_text(payload.get("service_area"), 120)
        experience = clean_text(payload.get("experience"), 1500)
        services = payload.get("services")
        contact_consent = payload.get("contact_consent") is True
        if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            return error_response("Enter your name and a valid email address.", 400)
        if not re.fullmatch(r"(?:\+91)?[6-9]\d{9}", normalized_phone):
            return error_response("Enter a valid Indian mobile number.", 400)
        if not service_area or not experience:
            return error_response("Add your service area and relevant experience.", 400)
        if not isinstance(services, list) or not services or any(
            not isinstance(service, str) or service not in SERVICE_NAMES for service in services
        ):
            return error_response("Choose at least one valid service category.", 400)
        if not contact_consent:
            return error_response("Please allow Morrow to contact you about your application.", 400)

        cursor = get_db().execute(
            """INSERT INTO agent_applications (name, email, phone, service_area, services_json, experience)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, email, normalized_phone, service_area, json.dumps(sorted(set(services))), experience),
        )
        get_db().commit()
        return jsonify(success=True, application_id=cursor.lastrowid), 201

    @app.get("/api/bookings")
    def list_bookings():
        user = current_user()
        if user is None:
            return error_response("Log in to see your bookings.", 401)

        rows = get_db().execute(
            """SELECT id, service, address, phone, preferred_date, preferred_window, notes, payment_method, status,
                      quote_amount_paise, quote_before_discount_paise, discount_amount_paise,
                      payment_status, created_at
               FROM bookings WHERE user_id = ? ORDER BY id DESC""",
            (user["id"],),
        ).fetchall()
        return jsonify(
            bookings=[
                {
                    "id": row["id"],
                    "service": row["service"],
                    "address": row["address"],
                    "phone": row["phone"],
                    "preferred_date": row["preferred_date"],
                    "preferred_window": row["preferred_window"],
                    "notes": row["notes"],
                    "payment_method": row["payment_method"] or "online",
                    "status": row["status"],
                    "quote_amount_paise": row["quote_amount_paise"],
                    "quote_before_discount_paise": row["quote_before_discount_paise"],
                    "discount_amount_paise": row["discount_amount_paise"],
                    "payment_status": row["payment_status"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        )

    @app.post("/api/bookings")
    @limiter.limit("10 per hour")
    def create_booking():
        user = current_user()
        if user is None:
            return error_response("Log in to make a booking.", 401)

        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)

        payload = json_payload()
        service = clean_text(payload.get("service"), 100)
        address = clean_text(payload.get("address"), 200)
        phone = clean_text(payload.get("phone"), 32)
        normalized_phone = re.sub(r"[\s-]", "", phone)
        preferred_date = clean_text(payload.get("preferred_date"), 50)
        preferred_window = clean_text(payload.get("preferred_window"), 20)
        notes = clean_text(payload.get("notes"), 1500)
        payment_method = clean_text(payload.get("payment_method"), 20)
        if payment_method not in {"online", "offline"}:
            payment_method = "online"

        if service not in SERVICE_NAMES:
            return error_response("Choose a valid service.", 400)
        if not address or not phone or not preferred_date or preferred_window not in TIME_WINDOWS:
            return error_response("Complete the booking details and choose a valid time window.", 400)
        if normalized_phone.startswith("+91"):
            normalized_phone = normalized_phone[3:]
        if not re.fullmatch(r"[6-9]\d{9}", normalized_phone):
            return error_response("Enter a valid Indian mobile number.", 400)
        phone = f"+91{normalized_phone}"

        try:
            booking_date = date.fromisoformat(preferred_date)
        except ValueError:
            return error_response("Use a valid date in YYYY-MM-DD format.", 400)

        if booking_date < date.today():
            return error_response("The booking date must be today or in the future.", 400)

        cursor = get_db().execute(
            """INSERT INTO bookings (user_id, service, address, phone, preferred_date, preferred_window, notes, payment_method)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user["id"], service, address, phone, preferred_date, preferred_window, notes, payment_method),
        )
        get_db().commit()

        booking = get_db().execute(
             """SELECT id, service, address, phone, preferred_date, preferred_window, notes, payment_method, status,
                 quote_amount_paise, quote_before_discount_paise, discount_amount_paise,
                 payment_status, created_at
             FROM bookings WHERE id = ?""",
            (cursor.lastrowid,),
        ).fetchone()
        return jsonify({
            "booking": {
                "id": booking["id"],
                "service": booking["service"],
                "address": booking["address"],
                "phone": booking["phone"],
                "preferred_date": booking["preferred_date"],
                "preferred_window": booking["preferred_window"],
                "notes": booking["notes"],
                "payment_method": booking["payment_method"] or "online",
                "status": booking["status"],
                "quote_amount_paise": booking["quote_amount_paise"],
                "quote_before_discount_paise": booking["quote_before_discount_paise"],
                "discount_amount_paise": booking["discount_amount_paise"],
                "payment_status": booking["payment_status"],
                "created_at": booking["created_at"],
            }
        }), 201

    @app.post("/api/logout")
    def logout():
        if not csrf_is_valid():
            return error_response("Refresh the page and try again.", 400)
        session.clear()
        return jsonify(success=True)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
