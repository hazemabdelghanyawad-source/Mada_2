import html
import re
import os
from collections import Counter
from io import BytesIO
from urllib.parse import quote

import pandas as pd
import uvicorn

from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi import HTTPException
import sqlite3
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from contextvars import ContextVar

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
except Exception:
    arabic_reshaper = None
    get_display = None




app = FastAPI(title="منصة مدى التعليمية الذكية")



SESSION_DAYS = 7
students_context = ContextVar("students_context", default=None)
teacher_context = ContextVar("teacher_context", default=None)


# MongoDB connection is read from .env / environment variable.
# Never hard-code the Atlas password in source code.
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from bson import ObjectId
from pymongo.errors import DuplicateKeyError

load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()

if not MONGODB_URI:
    raise RuntimeError(
        "MONGODB_URI is missing. Create a .env file next to this file and set MONGODB_URI=..."
    )

mongo_client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=5000,
)

mongo_db = mongo_client[os.getenv("MONGODB_DB", "mada")]
teachers_collection = mongo_db["teachers"]
sessions_collection = mongo_db["sessions"]
students_collection = mongo_db["students"]
reports_collection = mongo_db["reports"]


teachers_collection.create_index([("email", ASCENDING)], unique=True)
sessions_collection.create_index([("token", ASCENDING)], unique=True)
sessions_collection.create_index([("expires_at", ASCENDING)])
students_collection.create_index([("teacher_id", ASCENDING)])


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 180_000
    )
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 180_000
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def create_session(teacher_id):
    token = secrets.token_urlsafe(48)
    expires = datetime.utcnow() + timedelta(days=SESSION_DAYS)
    sessions_collection.insert_one({
        "token": token,
        "teacher_id": str(teacher_id),
        "expires_at": expires,
    })
    return token


def get_teacher(request):
    token = request.cookies.get("mada_session")
    if not token:
        return None

    session = sessions_collection.find_one({"token": token})
    if not session:
        return None

    expires_at = session.get("expires_at")
    if not isinstance(expires_at, datetime):
        sessions_collection.delete_one({"token": token})
        return None

    # Store UTC datetimes as naive values for compatibility with MongoDB/Python.
    if expires_at < datetime.utcnow():
        sessions_collection.delete_one({"token": token})
        return None

    teacher = None
    teacher_id = session.get("teacher_id")
    try:
        teacher = teachers_collection.find_one({"_id": ObjectId(teacher_id)})
    except Exception:
        teacher = teachers_collection.find_one({"_id": teacher_id})

    if not teacher:
        return None

    return {
        "id": str(teacher["_id"]),
        "name": teacher.get("name", ""),
        "email": teacher.get("email", ""),
        "expires_at": expires_at.isoformat(),
    }


def require_teacher(request):
    teacher = get_teacher(request)
    if not teacher:
        return None, RedirectResponse("/login", status_code=303)
    return teacher, None


def load_teacher_students(teacher_id):
    rows = students_collection.find({"teacher_id": str(teacher_id)}).sort("_id", ASCENDING)
    return [row.get("data", {}) for row in rows]


def save_teacher_students(teacher_id, students):
    teacher_id = str(teacher_id)
    students_collection.delete_many({"teacher_id": teacher_id})
    if students:
        students_collection.insert_many([
            {"teacher_id": teacher_id, "data": student}
            for student in students
        ])


def set_students_context(students):
    students_context.set(students)


def set_teacher_context(teacher):
    teacher_context.set(teacher)


def current_teacher():
    return teacher_context.get()


def current_students():
    value = students_context.get()
    return value if value is not None else students_data


def page_shell(title, body):
    return f"""
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{esc(title)} | منصة مدى</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                min-height: 100vh;
                font-family: Tahoma, Arial, sans-serif;
                background: linear-gradient(135deg, #f4fbff, #eef7ff);
                color: #17324d;
            }}
            .auth-wrap {{
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 24px;
            }}
            .auth-card {{
                width: min(460px, 100%);
                background: white;
                border: 1px solid #dcecf7;
                border-radius: 24px;
                padding: 34px;
                box-shadow: 0 18px 55px rgba(0, 86, 140, .10);
            }}
            .logo {{
                width: 58px; height: 58px; border-radius: 17px;
                background: #0094db; color: white;
                display:flex; align-items:center; justify-content:center;
                font-size: 25px; font-weight: 800; margin-bottom: 18px;
            }}
            h1 {{ margin: 0 0 8px; font-size: 27px; }}
            .muted {{ color:#71859a; line-height:1.7; margin-bottom:25px; }}
            label {{ display:block; font-weight:700; margin:15px 0 8px; }}
            input {{
                width:100%; padding:14px 15px; border:1px solid #d6e4ee;
                border-radius:12px; outline:none; font-size:15px;
            }}
            input:focus {{ border-color:#0094db; box-shadow:0 0 0 3px rgba(0,148,219,.10); }}
            button {{
                width:100%; border:0; border-radius:12px; padding:14px;
                margin-top:20px; background:#0094db; color:white;
                font-weight:800; font-size:16px; cursor:pointer;
            }}
            .switch {{ text-align:center; margin-top:20px; color:#71859a; }}
            a {{ color:#0094db; text-decoration:none; font-weight:700; }}
            .error {{
                background:#fff0f0; color:#b42318; border:1px solid #ffd0d0;
                border-radius:12px; padding:12px 14px; margin-bottom:16px;
            }}
            .brand-sub {{ color:#0094db; font-weight:800; margin-bottom:8px; }}
        </style>
    </head>
    <body>{body}</body>
    </html>
    """


def auth_form_html(mode="login", error=""):
    login = mode == "login"
    title = "تسجيل الدخول" if login else "إنشاء حساب معلم"
    subtitle = (
        "سجّل الدخول للوصول إلى بيانات طلابك ولوحة التحكم."
        if login else
        "أنشئ حسابك وابدأ بإدارة طلابك وتحليل أدائهم."
    )
    action = "/login" if login else "/signup"

    fields = ""
    if not login:
        fields += """
        <label>اسم المعلم</label>
        <input name="name" type="text" placeholder="مثال: أحمد محمد" required>
        """

    fields += """
        <label>البريد الإلكتروني</label>
        <input name="email" type="email" placeholder="teacher@example.com" required>
        <label>كلمة المرور</label>
        <input name="password" type="password" placeholder="••••••••" minlength="6" required>
    """

    switch = (
        'ليس لديك حساب؟ <a href="/signup">إنشاء حساب جديد</a>'
        if login else
        'لديك حساب بالفعل؟ <a href="/login">تسجيل الدخول</a>'
    )

    return page_shell(title, f"""
    <div class="auth-wrap">
        <div class="auth-card">
            <div class="logo">م</div>
            <div class="brand-sub">منصة مدى التعليمية الذكية</div>
            <h1>{title}</h1>
            <div class="muted">{subtitle}</div>
            {f'<div class="error">{esc(error)}</div>' if error else ''}
            <form method="post" action="{action}">
                {fields}
                <button type="submit">{title}</button>
            </form>
            <div class="switch">{switch}</div>
        </div>
    </div>
    """)






students_data = [
    {
        "student_id": "S001",
        "name": "أحمد محمد",
        "subject": "الرياضيات",
        "score": 92,
        "attendance_rate": 96,
        "exam_1": 88,
        "exam_2": 95,
        "homework": 94,
        "quiz": 91,
        "participation": 90,
        "parent_phone": "+201001234567",
    },
    {
        "student_id": "S002",
        "name": "سارة علي",
        "subject": "الرياضيات",
        "score": 76,
        "attendance_rate": 91,
        "exam_1": 72,
        "exam_2": 79,
        "homework": 75,
        "quiz": 68,
        "participation": 82,
        "parent_phone": "+201112345678",
    },
    {
        "student_id": "S003",
        "name": "عمر حسن",
        "subject": "العلوم",
        "score": 61,
        "attendance_rate": 78,
        "exam_1": 65,
        "exam_2": 58,
        "homework": 63,
        "quiz": 55,
        "participation": 60,
        "parent_phone": "+201223456789",
    },
    {
        "student_id": "S004",
        "name": "مريم خالد",
        "subject": "اللغة العربية",
        "score": 87,
        "attendance_rate": 94,
        "exam_1": 82,
        "exam_2": 90,
        "homework": 88,
        "quiz": 86,
        "participation": 92,
        "parent_phone": "+201098765432",
    },
]



# BOOKS

books_catalog = {
    "الرياضيات": [
        "أساسيات الرياضيات",
        "رحلة في عالم الأرقام",
        "الرياضيات بطريقة سهلة",
    ],
    "العلوم": [
        "عالم العلوم",
        "رحلة داخل جسم الإنسان",
        "اكتشف الكون",
    ],
    "اللغة العربية": [
        "فن القراءة",
        "أساسيات اللغة العربية",
        "مهارات الكتابة والتعبير",
    ],
}


# Arabic PDF 

import os
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ARABIC_FONT = "ArabicFont"

# Get the folder where this Python file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Arabic font stored inside the project
font_path = os.path.join(
    BASE_DIR,
    "fonts",
    "NotoNaskhArabic-Regular.ttf"
)

if not os.path.exists(font_path):
    font_path = os.path.join(
        BASE_DIR,
        "NotoNaskhArabic-VariableFont_wght.ttf"
    )

font_loaded = False

try:
    pdfmetrics.registerFont(
        TTFont(ARABIC_FONT, font_path)
    )
    font_loaded = True
except Exception as e:
    print(f"Arabic font could not be loaded: {e}")

# Fallback only if the Arabic font fails
if not font_loaded:
    ARABIC_FONT = "Helvetica"


def esc(value):
    return html.escape(str(value))

# Utility functions

def num(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def performance_level(score):

    if score >= 85:
        return "ممتاز"

    if score >= 70:
        return "جيد"

    if score >= 60:
        return "متوسط"

    return "بحاجة إلى دعم"


# Weekly Learning Plan Generator

def generate_weekly_plan(level, gaps, trend_class):
    """
    يحول التوصية إلى خطة أسبوعية فعلية (يوم بيوم)
    بحيث يعرف الطالب وولي الأمر والمدرس:
    ماذا يفعل؟ ومتى؟ وكيف نقيس التحسن؟

    نوع المهام وحجمها يتغيران حسب مستوى الطالب،
    بينما هيكل الأسبوع (7 أيام) يبقى ثابتًا.
    """

    main_gap = gaps[0] if gaps else "المهارات الحالية"
    second_gap = gaps[1] if len(gaps) > 1 else main_gap

    if level == "ممتاز":

        tasks = [
            ("السبت", f"تدريبات تحدٍ متقدمة على: {main_gap}", "تحدٍ"),
            ("الأحد", f"فيديو إثرائي متقدم عن {main_gap}", "تعلم"),
            ("الاثنين", "5 تمارين تطبيقية متقدمة", "تدريب"),
            ("الثلاثاء", "Quiz قصير بمستوى تحدٍ أعلى", "تقييم"),
            ("الأربعاء", "مراجعة الأخطاء إن وُجدت وتحليل سببها", "مراجعة"),
            ("الخميس", "اختبار قصير على المهارات المتقدمة", "تقييم"),
            ("الجمعة", "تقييم التقدم وتحديد التحدي القادم", "تقييم"),
        ]

    elif level == "جيد":

        tasks = [
            ("السبت", f"تمارين مركزة على {main_gap}", "تدريب"),
            ("الأحد", f"فيديو تعليمي يشرح {main_gap}", "تعلم"),
            ("الاثنين", "5 تمارين قصيرة ومتكررة", "تدريب"),
            ("الثلاثاء", "Quiz قصير لقياس الفهم", "تقييم"),
            ("الأربعاء", "مراجعة الأخطاء مع الطالب", "مراجعة"),
            ("الخميس", "اختبار قصير", "تقييم"),
            ("الجمعة", "تقييم التقدم وتحديد الخطوة التالية", "تقييم"),
        ]

    elif level == "متوسط":

        tasks = [
            ("السبت", f"خطوة تأسيسية في {main_gap} مع أمثلة محلولة", "تأسيس"),
            ("الأحد", f"فيديو تعليمي مبسط عن {main_gap}", "تعلم"),
            ("الاثنين", "4 تمارين موجهة خطوة بخطوة", "تدريب"),
            ("الثلاثاء", "Quiz قصير جدًا (3 أسئلة)", "تقييم"),
            ("الأربعاء", f"مراجعة الأخطاء و{second_gap}", "مراجعة"),
            ("الخميس", "اختبار قصير بمساعدة بسيطة عند الحاجة", "تقييم"),
            ("الجمعة", "تقييم التقدم مع ولي الأمر", "تقييم"),
        ]

    else:  # بحاجة إلى دعم

        tasks = [
            ("السبت", f"تأسيس {main_gap} بأمثلة محلولة خطوة بخطوة", "تأسيس"),
            ("الأحد", f"فيديو تعليمي مبسط جدًا عن {main_gap}", "تعلم"),
            ("الاثنين", "3 تمارين قصيرة موجهة بالكامل", "تدريب"),
            ("الثلاثاء", "مراجعة سريعة بدون تقييم رسمي", "مراجعة"),
            ("الأربعاء", "مراجعة الأخطاء مع شرح فردي", "مراجعة"),
            ("الخميس", "اختبار قصير جدًا (سؤالان)", "تقييم"),
            ("الجمعة", "جلسة متابعة فردية وتقييم التقدم", "متابعة"),
        ]

    # إذا كان الاتجاه في تراجع، نضيف دعمًا إضافيًا يوم التقييم
    if trend_class == "trend-down":
        day, task, ttype = tasks[3]
        tasks[3] = (day, task + " مع دعم إضافي قبل الاختبار", ttype)

    return [
        {"day": d, "task": t, "type": ty}
        for d, t, ty in tasks
    ]



# Student Analysis Engine

def analyze_student(student):

    score = max(
        0,
        min(100, num(student.get("score")))
    )

    attendance = max(
        0,
        min(100, num(student.get("attendance_rate")))
    )

    exam_1 = num(
        student.get("exam_1"),
        score
    )

    exam_2 = num(
        student.get("exam_2"),
        score
    )

    homework = num(
        student.get("homework"),
        score
    )

    quiz = num(
        student.get("quiz"),
        score
    )

    participation = num(
        student.get("participation"),
        score
    )

    subject = str(
        student.get(
            "subject",
            "الرياضيات"
        )
    )

    # -----------------------------------------------------
    # Components
    # -----------------------------------------------------

    components = {

        "الاختبارات": (
            exam_1 + exam_2
        ) / 2,

        "الواجبات": homework,

        "الاختبارات القصيرة": quiz,

        "المشاركة": participation,

        "الحضور": attendance,
    }

    # Trend

    trend_delta = exam_2 - exam_1

    # Weighted score

    weighted_score = (
        exam_1 * 0.25
        + exam_2 * 0.25
        + homework * 0.15
        + quiz * 0.15
        + participation * 0.10
        + attendance * 0.10
    )

    level = performance_level(score)

    # Strengths

    strengths = []

    if attendance >= 90:
        strengths.append(
            "الانتظام في الحضور"
        )

    if homework >= 85:
        strengths.append(
            "الالتزام بالواجبات"
        )

    if quiz >= 85:
        strengths.append(
            "الأداء في الاختبارات القصيرة"
        )

    if participation >= 85:
        strengths.append(
            "المشاركة داخل الحصة"
        )

    if exam_2 >= exam_1 + 5:
        strengths.append(
            "وجود تحسن واضح في نتائج الاختبارات"
        )

    if not strengths:
        strengths.append(
            "وجود أساس يمكن البناء عليه"
        )

    # Weaknesses

    weaknesses = []

    if quiz < 65:
        weaknesses.append(
            "الاختبارات القصيرة"
        )

    if homework < 65:
        weaknesses.append(
            "الواجبات والتدريب المستمر"
        )

    if participation < 65:
        weaknesses.append(
            "المشاركة داخل الحصة"
        )

    if attendance < 75:
        weaknesses.append(
            "الانتظام في الحضور"
        )

    if exam_2 < exam_1 - 5:
        weaknesses.append(
            "انخفاض الأداء مقارنة بالاختبار السابق"
        )

    if not weaknesses:
        weaknesses.append(
            "الانتقال إلى تدريبات أكثر تحديًا"
        )

    # Learning gaps

    gap_threshold = 70

    learning_gaps = []

    if subject == "الرياضيات":

        if quiz < gap_threshold or score < gap_threshold:
            learning_gaps.append(
                "الكسور والنسب"
            )

        if homework < gap_threshold:
            learning_gaps.append(
                "الجبر والمعادلات"
            )

        if score < 60:
            learning_gaps.append(
                "العمليات الأساسية"
            )

        elif score >= 85:
            learning_gaps.append(
                "المسائل متعددة الخطوات"
            )

    elif subject == "العلوم":

        if quiz < gap_threshold or score < gap_threshold:
            learning_gaps.append(
                "المفاهيم الأساسية"
            )

        if homework < gap_threshold:
            learning_gaps.append(
                "التطبيق والاستنتاج العلمي"
            )

        if participation < gap_threshold:
            learning_gaps.append(
                "التجارب وربط المفاهيم بالحياة"
            )

    else:

        if quiz < gap_threshold:
            learning_gaps.append(
                "المفردات"
            )

        if homework < gap_threshold:
            learning_gaps.append(
                "القواعد"
            )

        if score < 70:
            learning_gaps.append(
                "القراءة والاستيعاب"
            )

        elif score >= 85:
            learning_gaps.append(
                "الكتابة والتعبير"
            )

    learning_gaps = list(
        dict.fromkeys(learning_gaps)
    )

    if not learning_gaps:
        learning_gaps = [
            "تطوير المهارات الحالية"
        ]

    # Risk classification

    risk_points = 0

    if score < 60:
        risk_points += 2

    elif score < 70:
        risk_points += 1

    if attendance < 75:
        risk_points += 2

    elif attendance < 85:
        risk_points += 1

    if quiz < 60:
        risk_points += 1

    if trend_delta < -5:
        risk_points += 2

    if risk_points >= 4:

        risk_level = "مرتفع"
        risk_class = "risk-high"

    elif risk_points >= 2:

        risk_level = "متوسط"
        risk_class = "risk-medium"

    else:

        risk_level = "منخفض"
        risk_class = "risk-low"


    # Trend

    if trend_delta >= 5:

        trend_text = (
            f"تحسن بمقدار "
            f"{trend_delta:.1f} نقطة"
        )

        trend_class = "trend-up"

    elif trend_delta <= -5:

        trend_text = (
            f"انخفاض بمقدار "
            f"{abs(trend_delta):.1f} نقطة"
        )

        trend_class = "trend-down"

    else:

        trend_text = (
            "الأداء مستقر تقريبًا"
        )

        trend_class = "trend-flat"

    # -----------------------------------------------------
    # Personalized Recommendation
    # -----------------------------------------------------

    student_name = student.get(
        "name",
        "الطالب"
    )

    main_gap = learning_gaps[0]

    if score >= 85:

        recommendation = (
            f"الطالب {student_name} يمتلك "
            f"مستوى قويًا في {subject}. "
            f"يُنصح بالانتقال إلى تدريبات "
            f"أكثر تحديًا في {main_gap} "
            f"مع الحفاظ على مستوى "
            f"الواجبات والاختبارات."
        )

    elif score >= 70:

        recommendation = (
            f"الطالب {student_name} لديه "
            f"أساس جيد في {subject}. "
            f"الأولوية الآن هي معالجة "
            f"فجوة {main_gap} من خلال "
            f"تدريبات قصيرة ومتكررة "
            f"ثم إعادة القياس."
        )

    elif score >= 60:

        recommendation = (
            f"الطالب {student_name} يحتاج "
            f"إلى خطة دعم منتظمة في {subject}. "
            f"ابدأ بـ {main_gap}، ثم انتقل "
            f"تدريجيًا إلى المهارات الأعلى."
        )

    else:

        recommendation = (
            f"الطالب {student_name} يحتاج "
            f"إلى تدخل تعليمي مبكر في {subject}. "
            f"ابدأ بتأسيس {main_gap}، "
            f"واستخدم مهام قصيرة مع "
            f"متابعة أسبوعية."
        )

    if attendance < 75:

        recommendation += (
            " كما يجب تحسين الانتظام في الحضور."
        )

    elif attendance >= 90:

        recommendation += (
            " انتظام الحضور نقطة قوة "
            "يمكن استغلالها في تسريع التحسن."
        )

    # -----------------------------------------------------
    # Teacher Plan
    # -----------------------------------------------------

    teacher_actions = [

        f"راجع مهارة: {main_gap} "
        "في الحصة القادمة.",

        "أعطِ الطالب 3 تدريبات مستهدفة "
        "بدلًا من واجب عام.",

        "راجع الأخطاء مع الطالب "
        "واطلب منه شرح طريقة الحل.",
    ]

    if risk_level == "مرتفع":

        teacher_actions.append(
            "حدد متابعة فردية قصيرة هذا الأسبوع."
        )

    else:

        teacher_actions.append(
            "أعد قياس المهارة المستهدفة "
            "في نهاية الأسبوع."
        )

    # -----------------------------------------------------
    # Student Plan
    # -----------------------------------------------------

    student_plan = [

        f"تعلم: {main_gap} لمدة 20 دقيقة.",

        "حل 3–5 تمارين قصيرة.",

        "اكتب أو سجّل الخطأ "
        "الذي تكرر معك.",

        "أعد اختبارًا قصيرًا "
        "في نهاية الأسبوع.",
    ]

    # -----------------------------------------------------
    # Parent Plan
    # -----------------------------------------------------

    parent_actions = [

        "اسأل الطالب ماذا تعلم اليوم "
        "بدلًا من التركيز على الدرجة فقط.",

        f"شجعه على التدريب على: {main_gap}.",

        "تابع تنفيذ هدف أسبوعي صغير "
        "لمدة 20 دقيقة في اليوم.",
    ]

    if attendance < 75:

        parent_actions.append(
            "ساعد في تحسين الانتظام في الحضور."
        )

    else:

        parent_actions.append(
            "احتفل بالتقدم وشجع الاستمرار."
        )

    # -----------------------------------------------------
    # Book recommendation
    # -----------------------------------------------------

    books = books_catalog.get(
        subject,
        []
    )

    suggested_book = (
        books[0]
        if books
        else "مصدر تعليمي مناسب للمادة"
    )

    # -----------------------------------------------------
    # Weekly Goal
    # -----------------------------------------------------

    weekly_goal = (
        f"رفع أداء الطالب في {main_gap} "
        f"بمقدار 5 نقاط على الأقل "
        f"في القياس القادم."
    )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    status_summary = (
        f"المستوى الحالي: {level}. "
        f"الاتجاه: {trend_text}. "
        f"مستوى المخاطرة: {risk_level}."
    )

    # -----------------------------------------------------
    # Weekly learning plan (day by day)
    # -----------------------------------------------------

    weekly_plan = generate_weekly_plan(
        level,
        learning_gaps,
        trend_class,
    )

    return {

        "performance_level": level,

        "weighted_score":
            round(weighted_score, 1),

        "strengths":
            strengths,

        "weaknesses":
            weaknesses,

        "learning_gaps":
            learning_gaps,

        "trend_delta":
            round(trend_delta, 1),

        "trend_text":
            trend_text,

        "trend_class":
            trend_class,

        "risk_level":
            risk_level,

        "risk_class":
            risk_class,

        "status_summary":
            status_summary,

        "recommendation":
            recommendation,

        "teacher_actions":
            teacher_actions,

        "student_plan":
            student_plan,

        "parent_actions":
            parent_actions,

        "weekly_goal":
            weekly_goal,

        "suggested_book":
            suggested_book,

        "weekly_plan":
            weekly_plan,

        "components": {
            k: round(v, 1)
            for k, v in components.items()
        },
    }


# =========================================================
# Class Analytics Engine  (المرحلة 8 — Class Analytics)
# =========================================================
#
# مش بس تحليل الطالب. هنا بنحلل الفصل كله:
#   - متوسط الفصل
#   - توزيع الطلاب على مستويات الأداء (ممتاز / جيد / متوسط / بحاجة لدعم)
#   - أكثر فجوة تعلم (مهارة) يعاني منها الطلاب في الفصل
#

# الترتيب الثابت للمستويات حتى يظهر الرسم دائمًا بنفس الترتيب المنطقي.
PERFORMANCE_LEVELS_ORDER = [
    "ممتاز",
    "جيد",
    "متوسط",
    "بحاجة إلى دعم",
]


def analyze_class(students):
    """
    يحلل الفصل بالكامل بدلًا من طالب واحد فقط.

    يعتمد على analyze_student لكل طالب، ثم يجمع النتائج على
    مستوى الفصل: متوسط الدرجات، توزيع المستويات، وأكثر فجوات
    التعلم شيوعًا بين الطلاب — وهي المعلومة الأهم للمدرس لأنها
    تحدد على أي مهارة يجب أن يركّز في الحصة القادمة.
    """

    analyzed = [
        (student, analyze_student(student))
        for student in students
    ]

    total = len(analyzed)

    # -----------------------------------------------------
    # متوسط الفصل
    # -----------------------------------------------------

    class_average = (
        sum(num(s.get("score")) for s, _ in analyzed) / total
        if total else 0.0
    )

    # -----------------------------------------------------
    # توزيع مستويات الأداء
    # -----------------------------------------------------

    level_counts = {level: 0 for level in PERFORMANCE_LEVELS_ORDER}

    for _, ai in analyzed:
        level = ai["performance_level"]
        level_counts[level] = level_counts.get(level, 0) + 1

    level_distribution = [
        {
            "level": level,
            "count": level_counts.get(level, 0),
            "percentage": (
                round(100 * level_counts.get(level, 0) / total, 1)
                if total else 0.0
            ),
        }
        for level in PERFORMANCE_LEVELS_ORDER
    ]

    # -----------------------------------------------------
    # أكثر فجوات التعلم (المهارات) شيوعًا في الفصل
    # -----------------------------------------------------

    gap_counter = Counter()

    for _, ai in analyzed:
        # نحسب كل فجوة مرة واحدة لكل طالب حتى لا يتضخم العدد
        # لو تكررت نفس الفجوة أكثر من مرة لنفس الطالب.
        for gap in set(ai["learning_gaps"]):
            gap_counter[gap] += 1

    gap_ranking = [
        {
            "gap": gap,
            "count": count,
            "percentage": (
                round(100 * count / total, 1)
                if total else 0.0
            ),
        }
        for gap, count in gap_counter.most_common()
    ]

    top_gap = gap_ranking[0] if gap_ranking else None

    # -----------------------------------------------------
    # ملاحظة تلقائية للمدرس
    # -----------------------------------------------------

    if top_gap:
        class_insight = (
            f"أكثر مهارة يعاني منها الطلاب هي "
            f"\"{top_gap['gap']}\" — "
            f"يواجه فيها {top_gap['count']} من أصل {total} طالبًا "
            f"({top_gap['percentage']:.0f}%) صعوبة. "
            f"يُنصح بتخصيص جزء من الحصة القادمة لمعالجتها بشكل جماعي."
        )
    else:
        class_insight = (
            "لا توجد بيانات كافية حاليًا لاستخراج فجوات تعلم مشتركة."
        )

    return {
        "total_students": total,
        "class_average": round(class_average, 1),
        "level_distribution": level_distribution,
        "gap_ranking": gap_ranking,
        "top_gap": top_gap,
        "class_insight": class_insight,
    }


# =========================================================
# HTML helpers
# =========================================================

def bar_html(
    label,
    value,
    css_class="bar-blue"
):

    value = max(
        0,
        min(100, num(value))
    )

    return f"""
    <div class="bar-row">

        <div class="bar-label">

            <span>
                {esc(label)}
            </span>

            <strong>
                {value:.0f}%
            </strong>

        </div>

        <div class="bar-track">

            <div
                class="bar-fill {css_class}"
                style="width:{value:.0f}%"
            ></div>

        </div>

    </div>
    """


def weekly_plan_table_html(plan):

    type_class = {
        "تعلم": "wp-learn",
        "تدريب": "wp-practice",
        "تقييم": "wp-assess",
        "مراجعة": "wp-review",
        "تأسيس": "wp-foundation",
        "تحدٍ": "wp-challenge",
        "متابعة": "wp-followup",
    }

    rows = "".join(

        f"""
        <tr>
            <td class="wp-day">{esc(item['day'])}</td>
            <td class="wp-task">{esc(item['task'])}</td>
            <td>
                <span class="wp-tag {type_class.get(item['type'], 'wp-practice')}">
                    {esc(item['type'])}
                </span>
            </td>
        </tr>
        """

        for item in plan
    )

    return f"""
    <div class="table-wrap">
        <table class="weekly-plan-table">
            <thead>
                <tr>
                    <th>اليوم</th>
                    <th>المهمة</th>
                    <th>النوع</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def list_html(
    items,
    icon="✓"
):

    return "".join(

        f"""
        <li>
            <span class="list-icon">
                {icon}
            </span>

            {esc(item)}
        </li>
        """

        for item in items
    )


# =========================================================
# Class Analytics HTML helpers  (المرحلة 8)
# =========================================================

# لون مميز لكل مستوى أداء حتى يسهل على المدرس القراءة بسرعة.
LEVEL_STYLE = {
    "ممتاز": "level-excellent",
    "جيد": "level-good",
    "متوسط": "level-medium",
    "بحاجة إلى دعم": "level-support",
}


def class_level_distribution_html(level_distribution):
    """
    يبني رسم الأعمدة الأفقية لتوزيع الفصل على مستويات الأداء:
    ممتاز / جيد / متوسط / بحاجة لدعم — كل مستوى بلونه ونسبته.
    """

    return "".join(

        f"""
        <div class="level-row">
            <div class="level-row-head">
                <span class="level-dot {LEVEL_STYLE.get(item['level'], 'level-good')}"></span>
                <span class="level-name">{esc(item['level'])}</span>
                <span class="level-count">({item['count']} طالب)</span>
                <strong class="level-pct">{item['percentage']:.0f}%</strong>
            </div>
            <div class="level-track">
                <div
                    class="level-fill {LEVEL_STYLE.get(item['level'], 'level-good')}"
                    style="width:{item['percentage']:.0f}%"
                ></div>
            </div>
        </div>
        """

        for item in level_distribution
    )


def class_gap_ranking_html(gap_ranking, total_students, max_items=5):
    """
    يبني قائمة مرتبة بأكثر فجوات التعلم (المهارات) شيوعًا بين طلاب
    الفصل، مع نسبة الطلاب المتأثرين بكل فجوة — لمساعدة المدرس على
    تحديد أولوية المراجعة الجماعية.
    """

    if not gap_ranking:
        return (
            '<div class="empty" style="padding:26px;">'
            "لا توجد بيانات كافية لاستخراج فجوات تعلم مشتركة."
            "</div>"
        )

    rows = ""

    for index, item in enumerate(gap_ranking[:max_items]):

        is_top = index == 0

        rows += f"""
        <div class="gap-rank-row {'gap-rank-top' if is_top else ''}">
            <div class="gap-rank-left">
                <span class="gap-rank-number">{index + 1}</span>
                <span class="gap-rank-name">{esc(item['gap'])}</span>
            </div>
            <div class="gap-rank-right">
                <div class="gap-rank-track">
                    <div class="gap-rank-fill" style="width:{item['percentage']:.0f}%"></div>
                </div>
                <span class="gap-rank-pct">{item['percentage']:.0f}%</span>
                <span class="gap-rank-count">{item['count']}/{total_students}</span>
            </div>
        </div>
        """

    return rows


def class_top_gap_alert_html(top_gap, total_students):
    """
    صندوق تنبيه واضح للمدرس يوضح أهم فجوة تعلم على مستوى الفصل —
    هذه هي المعلومة التي يجب أن تُرى فورًا بدون الحاجة لقراءة كل شيء.
    """

    if not top_gap:
        return ""

    return f"""
    <div class="gap-alert">
        <div class="gap-alert-icon">⚠️</div>
        <div class="gap-alert-body">
            <strong>
                أكثر مهارة يعاني منها الطلاب: {esc(top_gap['gap'])}
            </strong>
            <p>
                {top_gap['count']} من أصل {total_students} طالبًا
                ({top_gap['percentage']:.0f}%) يحتاجون دعمًا في هذه المهارة.
                يُنصح بتخصيص جزء من الحصة القادمة لمعالجتها بشكل جماعي.
            </p>
        </div>
    </div>
    """


# =========================================================
# PROFESSIONAL PDF HELPERS
# =========================================================

from reportlab.lib.enums import TA_RIGHT, TA_CENTER
from reportlab.platypus import (
    Paragraph,
    Table,
    TableStyle,
    Spacer,
    KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.pdfmetrics import stringWidth


# ---------------------------------------------------------
# Arabic text
# ---------------------------------------------------------

def ar(text):
    text = str(text)

    if arabic_reshaper and get_display:
        try:
            return get_display(
                arabic_reshaper.reshape(text)
            )
        except Exception:
            return text

    return text


# ---------------------------------------------------------
# Wrap Arabic text
# ---------------------------------------------------------

def wrap_text(text, max_chars=65):

    words = str(text).split()

    lines = []
    current = ""

    for word in words:

        candidate = (
            f"{current} {word}"
        ).strip()

        if len(candidate) <= max_chars:

            current = candidate

        else:

            if current:
                lines.append(current)

            current = word

    if current:
        lines.append(current)

    return lines


# ---------------------------------------------------------
# Paragraph helper
# ---------------------------------------------------------

def pdf_paragraph(
    text,
    font_size=10,
    color="#334155",
    leading=16,
    alignment=TA_RIGHT
):

    style = ParagraphStyle(
        "ArabicStyle",
        fontName=ARABIC_FONT,
        fontSize=font_size,
        leading=leading,
        textColor=colors.HexColor(color),
        alignment=alignment,
        spaceAfter=0,
        spaceBefore=0,
    )

    return Paragraph(
        ar(text),
        style
    )


# =========================================================
# DRAW HEADER
# =========================================================

def draw_pdf_header(pdf, width, height, student):

    # Main header
    pdf.setFillColor(
        colors.HexColor("#2563EB")
    )

    pdf.roundRect(
        35,
        height - 120,
        width - 70,
        78,
        14,
        fill=1,
        stroke=0
    )

    # Title
    pdf.setFillColor(colors.white)

    pdf.setFont(
        ARABIC_FONT,
        20
    )

    pdf.drawRightString(
        width - 55,
        height - 70,
        ar("منصة مدى التعليمية الذكية")
    )

    # Subtitle
    pdf.setFont(
        ARABIC_FONT,
        9
    )

    pdf.drawRightString(
        width - 55,
        height - 91,
        ar(
            "تقرير الأداء والتحليل التعليمي الشخصي"
        )
    )

    # Student name
    pdf.setFont(
        ARABIC_FONT,
        11
    )

    pdf.drawString(
        55,
        height - 91,
        ar(
            str(student.get("name", ""))
        )
    )


# =========================================================
# FOOTER
# =========================================================

def draw_pdf_footer(
    pdf,
    width,
    page_number
):

    pdf.setStrokeColor(
        colors.HexColor("#E2E8F0")
    )

    pdf.line(
        45,
        42,
        width - 45,
        42
    )

    pdf.setFillColor(
        colors.HexColor("#64748B")
    )

    pdf.setFont(
        ARABIC_FONT,
        7
    )

    pdf.drawCentredString(
        width / 2,
        27,
        ar(
            f"منصة مدى التعليمية الذكية © 2026   |   صفحة {page_number}"
        )
    )


# =========================================================
# SECTION TITLE
# =========================================================

def draw_section_title(
    pdf,
    width,
    y,
    title
):

    pdf.setFillColor(
        colors.HexColor("#0F172A")
    )

    pdf.setFont(
        ARABIC_FONT,
        14
    )

    pdf.drawRightString(
        width - 55,
        y,
        ar(title)
    )

    # Blue line
    pdf.setFillColor(
        colors.HexColor("#2563EB")
    )

    pdf.roundRect(
        width - 145,
        y - 8,
        90,
        3,
        2,
        fill=1,
        stroke=0
    )

    return y - 28


# =========================================================
# KPI CARD
# =========================================================

def draw_kpi_card(
    pdf,
    x,
    y,
    width,
    height,
    title,
    value,
    accent="#2563EB"
):

    pdf.setFillColor(
        colors.HexColor("#FFFFFF")
    )

    pdf.roundRect(
        x,
        y,
        width,
        height,
        10,
        fill=1,
        stroke=0
    )

    # Border
    pdf.setStrokeColor(
        colors.HexColor("#E2E8F0")
    )

    pdf.roundRect(
        x,
        y,
        width,
        height,
        10,
        fill=0,
        stroke=1
    )

    # Accent
    pdf.setFillColor(
        colors.HexColor(accent)
    )

    pdf.roundRect(
        x,
        y,
        5,
        height,
        3,
        fill=1,
        stroke=0
    )

    # Title
    pdf.setFillColor(
        colors.HexColor("#64748B")
    )

    pdf.setFont(
        ARABIC_FONT,
        8
    )

    pdf.drawRightString(
        x + width - 12,
        y + height - 18,
        ar(title)
    )

    # Value
    pdf.setFillColor(
        colors.HexColor("#0F172A")
    )

    pdf.setFont(
        ARABIC_FONT,
        13
    )

    pdf.drawRightString(
        x + width - 12,
        y + 18,
        ar(value)
    )


# =========================================================
# PERFORMANCE BARS
# =========================================================

def draw_performance_chart(
    pdf,
    width,
    y,
    components
):

    chart_x = 65
    chart_width = width - 120

    for label, value in components.items():

        value = max(
            0,
            min(100, float(value))
        )

        # Label
        pdf.setFillColor(
            colors.HexColor("#334155")
        )

        pdf.setFont(
            ARABIC_FONT,
            8
        )

        pdf.drawRightString(
            width - 55,
            y,
            ar(
                f"{label}  {value:.0f}%"
            )
        )

        y -= 10

        # Background
        pdf.setFillColor(
            colors.HexColor("#E2E8F0")
        )

        pdf.roundRect(
            chart_x,
            y,
            chart_width,
            10,
            5,
            fill=1,
            stroke=0
        )

        # Value
        pdf.setFillColor(
            colors.HexColor("#2563EB")
        )

        pdf.roundRect(
            chart_x,
            y,
            chart_width * value / 100,
            10,
            5,
            fill=1,
            stroke=0
        )

        y -= 25

    return y


# =========================================================
# TEXT CARD
# =========================================================

def draw_text_card(
    pdf,
    width,
    y,
    title,
    items,
    background="#F8FAFC",
    title_color="#2563EB"
):

    card_x = 55
    card_width = width - 110

    # Calculate height
    height = 48 + (
        min(len(items), 5) * 23
    )

    # Background
    pdf.setFillColor(
        colors.HexColor(background)
    )

    pdf.roundRect(
        card_x,
        y - height,
        card_width,
        height,
        12,
        fill=1,
        stroke=0
    )

    # Title
    pdf.setFillColor(
        colors.HexColor(title_color)
    )

    pdf.setFont(
        ARABIC_FONT,
        11
    )

    pdf.drawRightString(
        width - 70,
        y - 25,
        ar(title)
    )

    # Items
    yy = y - 48

    pdf.setFillColor(
        colors.HexColor("#334155")
    )

    pdf.setFont(
        ARABIC_FONT,
        8
    )

    for item in items[:5]:

        pdf.drawRightString(
            width - 75,
            yy,
            ar("• " + str(item))
        )

        yy -= 23

    return y - height - 15


# =========================================================
# RECOMMENDATION CARD
# =========================================================

def draw_recommendation_card(
    pdf,
    width,
    y,
    recommendation
):

    card_x = 55
    card_width = width - 110

    lines = wrap_text(
        recommendation,
        65
    )

    lines = lines[:5]

    card_height = (
        60 + len(lines) * 16
    )

    pdf.setFillColor(
        colors.HexColor("#EFF6FF")
    )

    pdf.roundRect(
        card_x,
        y - card_height,
        card_width,
        card_height,
        12,
        fill=1,
        stroke=0
    )

    # Accent
    pdf.setFillColor(
        colors.HexColor("#2563EB")
    )

    pdf.roundRect(
        card_x,
        y - card_height,
        5,
        card_height,
        3,
        fill=1,
        stroke=0
    )

    # Title
    pdf.setFillColor(
        colors.HexColor("#1D4ED8")
    )

    pdf.setFont(
        ARABIC_FONT,
        12
    )

    pdf.drawRightString(
        width - 70,
        y - 25,
        ar("التوصية التعليمية الذكية")
    )

    # Text
    pdf.setFillColor(
        colors.HexColor("#334155")
    )

    pdf.setFont(
        ARABIC_FONT,
        8
    )

    yy = y - 48

    for line in lines:

        pdf.drawRightString(
            width - 70,
            yy,
            ar(line)
        )

        yy -= 16

    return y - card_height - 15


# =========================================================
# WEEKLY GOAL
# =========================================================

def draw_goal_card(
    pdf,
    width,
    y,
    goal
):

    card_x = 55
    card_width = width - 110

    pdf.setFillColor(
        colors.HexColor("#FFFBEB")
    )

    pdf.roundRect(
        card_x,
        y - 78,
        card_width,
        68,
        12,
        fill=1,
        stroke=0
    )

    pdf.setFillColor(
        colors.HexColor("#D97706")
    )

    pdf.setFont(
        ARABIC_FONT,
        11
    )

    pdf.drawRightString(
        width - 70,
        y - 30,
        ar("🎯 الهدف الأسبوعي")
    )

    pdf.setFillColor(
        colors.HexColor("#78350F")
    )

    pdf.setFont(
        ARABIC_FONT,
        8
    )

    lines = wrap_text(
        goal,
        70
    )

    yy = y - 48

    for line in lines[:2]:

        pdf.drawRightString(
            width - 70,
            yy,
            ar(line)
        )

        yy -= 15

    return y - 95

def draw_pdf_section(pdf, title, items, x, y, width):
    """
    رسم قسم منظم داخل تقرير PDF
    """

    items = items if items else ["لا توجد بيانات متاحة"]

    # حساب الارتفاع حسب عدد العناصر
    visible_items = items[:5]
    height = 42 + (len(visible_items) * 20)

    # منع القسم من الخروج من الصفحة
    if y - height < 45:
        pdf.showPage()
        y = A4[1] - 60

    # خلفية القسم
    pdf.setFillColor(colors.HexColor("#F8FAFC"))
    pdf.roundRect(
        x,
        y - height,
        width,
        height,
        10,
        fill=1,
        stroke=0
    )

    # الشريط الجانبي
    pdf.setFillColor(colors.HexColor("#2563EB"))
    pdf.roundRect(
        x,
        y - height,
        5,
        height,
        5,
        fill=1,
        stroke=0
    )

    # عنوان القسم
    pdf.setFillColor(colors.HexColor("#1E3A8A"))
    pdf.setFont(ARABIC_FONT, 12)

    pdf.drawRightString(
        x + width - 15,
        y - 22,
        ar(title)
    )

    # العناصر
    pdf.setFillColor(colors.HexColor("#334155"))
    pdf.setFont(ARABIC_FONT, 9)

    current_y = y - 43

    for item in visible_items:

        # نقطة
        pdf.setFillColor(colors.HexColor("#2563EB"))
        pdf.circle(
            x + width - 18,
            current_y + 3,
            2,
            fill=1,
            stroke=0
        )

        # النص
        pdf.setFillColor(colors.HexColor("#334155"))

        lines = wrap_text(item, 80)

        for line in lines[:2]:
            pdf.drawRightString(
                x + width - 28,
                current_y,
                ar(line)
            )
            current_y -= 13

        current_y -= 5

    return y - height - 15


def draw_weekly_plan_table(pdf, width, y, plan):
    """
    رسم جدول خطة التعلم الأسبوعية (اليوم / المهمة / النوع)
    """

    x = 55
    table_width = width - 110

    day_col_w = 65
    type_col_w = 70
    task_col_w = table_width - day_col_w - type_col_w

    row_height = 26
    header_height = 20
    table_height = header_height + len(plan) * row_height + 25

    if y - table_height < 60:
        pdf.showPage()
        y = A4[1] - 60

    # Title
    pdf.setFillColor(colors.HexColor("#1e293b"))
    pdf.setFont(ARABIC_FONT, 14)
    pdf.drawRightString(
        x + table_width,
        y,
        ar("خطة التعلم الأسبوعية")
    )

    y -= 22

    # Header row
    pdf.setFillColor(colors.HexColor("#2563eb"))
    pdf.roundRect(x, y - header_height, table_width, header_height, 6, fill=1, stroke=0)

    pdf.setFillColor(colors.white)
    pdf.setFont(ARABIC_FONT, 9)
    pdf.drawCentredString(x + table_width - day_col_w / 2, y - header_height + 6, ar("اليوم"))
    pdf.drawCentredString(x + table_width - day_col_w - task_col_w / 2, y - header_height + 6, ar("المهمة"))
    pdf.drawCentredString(x + type_col_w / 2, y - header_height + 6, ar("النوع"))

    y -= header_height

    for i, item in enumerate(plan):

        row_bg = "#F8FAFC" if i % 2 == 0 else "#FFFFFF"

        pdf.setFillColor(colors.HexColor(row_bg))
        pdf.rect(x, y - row_height, table_width, row_height, fill=1, stroke=0)

        pdf.setFillColor(colors.HexColor("#0f172a"))
        pdf.setFont(ARABIC_FONT, 9)
        pdf.drawCentredString(
            x + table_width - day_col_w / 2,
            y - row_height / 2 - 3,
            ar(item["day"])
        )

        pdf.setFillColor(colors.HexColor("#334155"))
        pdf.setFont(ARABIC_FONT, 8)
        task_lines = wrap_text(item["task"], 40)
        pdf.drawRightString(
            x + table_width - day_col_w - 8,
            y - row_height / 2 - 3,
            ar(task_lines[0])
        )

        pdf.setFillColor(colors.HexColor("#2563eb"))
        pdf.setFont(ARABIC_FONT, 8)
        pdf.drawCentredString(
            x + type_col_w / 2,
            y - row_height / 2 - 3,
            ar(item["type"])
        )

        y -= row_height

    pdf.setStrokeColor(colors.HexColor("#E2E8F0"))
    pdf.line(x, y, x + table_width, y)

    return y - 20


def create_student_pdf(student):

    ai = analyze_student(student)

    buffer = BytesIO()

    pdf = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    width, height = A4

    # -----------------------------------------------------
    # Header
    # -----------------------------------------------------

    pdf.setFillColor(
        colors.HexColor("#2563eb")
    )

    pdf.roundRect(
        35,
        height - 115,
        width - 70,
        70,
        14,
        fill=1,
        stroke=0
    )

    pdf.setFillColor(
        colors.white
    )

    pdf.setFont(
        ARABIC_FONT,
        20
    )

    pdf.drawRightString(
        width - 55,
        height - 75,
        ar("منصة مدى التعليمية الذكية")
    )

    pdf.setFont(
        ARABIC_FONT,
        10
    )

    pdf.drawRightString(
        width - 55,
        height - 95,
        ar(
            "تقرير الأداء والخطة التعليمية الشخصية"
        )
    )

    y = height - 145

    # -----------------------------------------------------
    # Student information
    # -----------------------------------------------------

    pdf.setFillColor(
        colors.HexColor("#1e293b")
    )

    pdf.setFont(
        ARABIC_FONT,
        15
    )

    pdf.drawRightString(
        width - 55,
        y,
        ar(
            f"الطالب: {student.get('name', 'غير معروف')}"
        )
    )

    y -= 30

    pdf.setFont(
        ARABIC_FONT,
        10
    )

    pdf.drawRightString(
        width - 55,
        y,
        ar(
            f"المادة: {student.get('subject', '')} | "
            f"الدرجة: {num(student.get('score')):.1f}% | "
            f"الحضور: "
            f"{num(student.get('attendance_rate')):.1f}%"
        )
    )

    y -= 35

    # -----------------------------------------------------
    # KPI boxes
    # -----------------------------------------------------

    kpis = [

        (
            "المستوى",
            ai["performance_level"]
        ),

        (
            "المخاطرة",
            ai["risk_level"]
        ),

        (
            "الاتجاه",
            ai["trend_text"]
        ),
    ]

    box_w = (
        width - 125
    ) / 3

    for i, (label, value) in enumerate(kpis):

        x = (
            55
            + i * (box_w + 7)
        )

        pdf.setFillColor(
            colors.HexColor("#f8fafc")
        )

        pdf.roundRect(
            x,
            y - 48,
            box_w,
            48,
            8,
            fill=1,
            stroke=0
        )

        pdf.setFillColor(
            colors.HexColor("#64748b")
        )

        pdf.setFont(
            ARABIC_FONT,
            8
        )

        pdf.drawCentredString(
            x + box_w / 2,
            y - 17,
            ar(label)
        )

        pdf.setFillColor(
            colors.HexColor("#1e293b")
        )

        pdf.setFont(
            ARABIC_FONT,
            10
        )

        pdf.drawCentredString(
            x + box_w / 2,
            y - 35,
            ar(value)
        )

    y -= 72

    # -----------------------------------------------------
    # Performance
    # -----------------------------------------------------

    pdf.setFillColor(
        colors.HexColor("#1e293b")
    )

    pdf.setFont(
        ARABIC_FONT,
        14
    )

    pdf.drawRightString(
        width - 55,
        y,
        ar("مؤشرات الأداء")
    )

    y -= 25

    for label, value in ai["components"].items():

        pdf.setFillColor(
            colors.HexColor("#e2e8f0")
        )

        pdf.roundRect(
            70,
            y - 8,
            220,
            16,
            6,
            fill=1,
            stroke=0
        )

        pdf.setFillColor(
            colors.HexColor("#2563eb")
        )

        pdf.roundRect(
            70,
            y - 8,
            220 * (
                value / 100
            ),
            16,
            6,
            fill=1,
            stroke=0
        )

        pdf.setFillColor(
            colors.HexColor("#334155")
        )

        pdf.setFont(
            ARABIC_FONT,
            8
        )

        pdf.drawString(
            305,
            y - 3,
            ar(
                f"{label}: {value:.0f}%"
            )
        )

        y -= 27

    y -= 10

    y = draw_pdf_section(
        pdf,
        "نقاط القوة",
        ai["strengths"],
        55,
        y,
        width - 110
    )

    y = draw_pdf_section(
        pdf,
        "نقاط الضعف",
        ai["weaknesses"],
        55,
        y,
        width - 110
    )

    # -----------------------------------------------------
    # New page
    # -----------------------------------------------------

    pdf.showPage()

    y = height - 65

    pdf.setFillColor(
        colors.HexColor("#2563eb")
    )

    pdf.setFont(
        ARABIC_FONT,
        18
    )

    pdf.drawRightString(
        width - 55,
        y,
        ar("الخطة التعليمية الشخصية")
    )

    y -= 35

    y = draw_pdf_section(
        pdf,
        "فجوات التعلم",
        ai["learning_gaps"],
        55,
        y,
        width - 110
    )

    y = draw_pdf_section(
        pdf,
        "خطة المدرس",
        ai["teacher_actions"],
        55,
        y,
        width - 110
    )

    y = draw_pdf_section(
        pdf,
        "خطة الطالب",
        ai["student_plan"],
        55,
        y,
        width - 110
    )

    y = draw_pdf_section(
        pdf,
        "دور ولي الأمر",
        ai["parent_actions"],
        55,
        y,
        width - 110
    )

    # -----------------------------------------------------
    # Weekly learning plan (day by day table)
    # -----------------------------------------------------

    y -= 5

    y = draw_weekly_plan_table(
        pdf,
        width,
        y,
        ai["weekly_plan"]
    )

    # -----------------------------------------------------
    # Weekly goal
    # -----------------------------------------------------

    y -= 5

    if y - 105 < 60:
        pdf.showPage()
        y = height - 60

    pdf.setFillColor(
        colors.HexColor("#fffbeb")
    )

    pdf.roundRect(
        55,
        y - 85,
        width - 110,
        75,
        10,
        fill=1,
        stroke=0
    )

    pdf.setFillColor(
        colors.HexColor("#92400e")
    )

    pdf.setFont(
        ARABIC_FONT,
        12
    )

    pdf.drawRightString(
        width - 70,
        y - 30,
        ar("الهدف الأسبوعي")
    )

    pdf.setFont(
        ARABIC_FONT,
        9
    )

    lines = wrap_text(
        ai["weekly_goal"],
        75
    )

    yy = y - 50

    for line in lines[:2]:

        pdf.drawRightString(
            width - 70,
            yy,
            ar(line)
        )

        yy -= 15

    y -= 105

    # -----------------------------------------------------
    # Recommendation
    # -----------------------------------------------------

    if y - 90 < 60:
        pdf.showPage()
        y = height - 60

    pdf.setFillColor(
        colors.HexColor("#eff6ff")
    )

    pdf.roundRect(
        55,
        y - 90,
        width - 110,
        80,
        10,
        fill=1,
        stroke=0
    )

    pdf.setFillColor(
        colors.HexColor("#1d4ed8")
    )

    pdf.setFont(
        ARABIC_FONT,
        12
    )

    pdf.drawRightString(
        width - 70,
        y - 30,
        ar("التوصية التعليمية الذكية")
    )

    pdf.setFillColor(
        colors.HexColor("#334155")
    )

    pdf.setFont(
        ARABIC_FONT,
        9
    )

    lines = wrap_text(
        ai["recommendation"],
        75
    )

    yy = y - 50

    for line in lines[:3]:

        pdf.drawRightString(
            width - 70,
            yy,
            ar(line)
        )

        yy -= 15

    # -----------------------------------------------------
    # Footer
    # -----------------------------------------------------

    pdf.setFillColor(
        colors.HexColor("#64748b")
    )

    pdf.setFont(
        ARABIC_FONT,
        8
    )

    pdf.drawCentredString(
        width / 2,
        25,
        ar(
            "منصة مدى التعليمية الذكية © 2026"
        )
    )

    pdf.save()

    buffer.seek(0)

    return buffer


# =========================================================
# HTML PAGE
# =========================================================

def _find_student(student_id):
    for student in current_students():
        if str(student.get("student_id")) == str(student_id):
            return student
    return None


# =========================================================
# WhatsApp Report Sharing
# =========================================================
#
# نستخدم رابط "wa.me" (WhatsApp Click-to-Chat) وهو رابط رسمي
# لا يحتاج أي مفتاح API أو حساب WhatsApp Business:
# يفتح محادثة واتساب مع رقم ولي الأمر ويضع نص التقرير جاهزًا
# للإرسال، ويبقى القرار النهائي بالإرسال بيد المستخدم (المعلم/الإدارة).
#
# ملاحظة: لو احتجتم إرسالًا تلقائيًا بالكامل بدون ضغط زر (عبر
# WhatsApp Business Cloud API الرسمي من Meta)، فهذا ممكن لاحقًا
# لكنه يتطلب: رقم واتساب بزنس موثّق، Access Token، وموافقة القالب
# (Message Template) من Meta — وهي بيانات اعتماد يجب أن يوفرها
# صاحب المنصة نفسه، ولذلك لم يتم تضمينها هنا.

def normalize_whatsapp_phone(phone):
    """
    ينظف رقم الهاتف ليصلح لرابط wa.me:
    يبقي الأرقام فقط (بدون +، مسافات، شرطات، أقواس).
    يرجع None إذا كان الرقم غير صالح (قصير جدًا أو غير موجود).
    """

    if not phone:
        return None

    digits_only = re.sub(r"\D", "", str(phone))

    if len(digits_only) < 8:
        return None

    return digits_only


def build_whatsapp_report_message(student, ai=None):
    """
    يبني نص تقرير مختصر وواضح لولي الأمر بصيغة عربية جاهزة للإرسال.
    """

    if ai is None:
        ai = analyze_student(student)

    name = student.get("name", "الطالب")
    subject = student.get("subject", "-")
    score = num(student.get("score"))
    attendance = num(student.get("attendance_rate"))

    lines = [
        f"📊 تقرير أداء الطالب/ة: {name}",
        f"المادة: {subject}",
        "",
        f"• الدرجة الموزونة: {ai['weighted_score']:.0f}%",
        f"• نسبة الحضور: {attendance:.0f}%",
        f"• المستوى العام: {ai['performance_level']}",
        f"• مستوى المخاطرة: {ai['risk_level']}",
        "",
        "🎯 التوصية:",
        ai["recommendation"],
        "",
        "🏠 دور ولي الأمر هذا الأسبوع:",
    ]

    for action in ai["parent_actions"][:3]:
        lines.append(f"- {action}")

    lines.append("")
    lines.append("منصة مدى التعليمية الذكية")

    return "\n".join(lines)


def build_whatsapp_share_link(student, ai=None):
    """
    يرجع رابط واتساب جاهز للإرسال (wa.me) مع نص التقرير،
    أو None إذا لم يكن هناك رقم هاتف صالح لولي الأمر مسجّل.
    """

    phone = normalize_whatsapp_phone(student.get("parent_phone"))

    if not phone:
        return None

    message = build_whatsapp_report_message(student, ai)

    return f"https://wa.me/{phone}?text={quote(message)}"


def build_bulk_whatsapp_links(students):
    """
    يجهز روابط واتساب لكل طلاب الفصل دفعة واحدة.

    ملاحظة مهمة: رابط wa.me لا يدعم إرسال نفس الرسالة لعدة أرقام
    برابط واحد (هذه خاصية WhatsApp Business Cloud API فقط، وتحتاج
    اعتماد رسمي من Meta). لذلك يتم تجهيز رابط منفصل لكل ولي أمر،
    ويقوم الزر في الواجهة بفتحها كلها دفعة واحدة في نوافذ منفصلة
    حتى لا يضطر المدرس لفتح كل تقرير يدويًا.

    يرجع (ready, missing):
    - ready: الطلاب الذين لديهم رقم واتساب صالح لولي الأمر.
    - missing: الطلاب بدون رقم واتساب مسجل لولي الأمر.
    """

    ready = []
    missing = []

    for student in students:
        ai = analyze_student(student)
        link = build_whatsapp_share_link(student, ai)

        entry = {
            "student_id": student.get("student_id"),
            "name": student.get("name"),
            "subject": student.get("subject"),
        }

        if link:
            entry["link"] = link
            ready.append(entry)
        else:
            missing.append(entry)

    return ready, missing


def send_all_reports_html():
    """
    صفحة "إرسال كل التقارير لأولياء الأمور دفعة واحدة":
    زر واحد يفتح محادثة واتساب منفصلة لكل ولي أمر مع تقرير ابنه/ابنته
    جاهزًا للإرسال، بالإضافة لقائمة بكل الروابط كخطة بديلة لو حجب
    المتصفح النوافذ المنبثقة.
    """

    ready, missing = build_bulk_whatsapp_links(current_students())

    total = len(current_students())

    ready_rows = "".join(
        f"""
        <div class="send-row">
            <div class="send-info">
                <strong>{esc(item['name'])}</strong>
                <span>{esc(item['subject'])} · {esc(item['student_id'])}</span>
            </div>
            <a class="btn btn-whatsapp" href="{esc(item['link'])}"
               target="_blank" rel="noopener">فتح واتساب</a>
        </div>
        """
        for item in ready
    )

    if not ready_rows:
        ready_rows = '<p class="empty-note">لا يوجد طلاب لديهم رقم واتساب صالح لولي الأمر حاليًا.</p>'

    missing_section = ""

    if missing:
        missing_rows = "".join(
            f"""
            <div class="send-row send-row-missing">
                <div class="send-info">
                    <strong>{esc(item['name'])}</strong>
                    <span>{esc(item['subject'])} · {esc(item['student_id'])}</span>
                </div>
                <span class="btn btn-disabled">لا يوجد رقم مسجل</span>
            </div>
            """
            for item in missing
        )

        missing_section = f"""
        <h2 class="section-title">بدون رقم واتساب مسجل ({len(missing)})</h2>
        <div class="send-list">
            {missing_rows}
        </div>
        """

    # روابط الطلاب الجاهزين فقط، مُمرَّرة إلى JS لفتحها كلها بضغطة واحدة.
    links_js_array = ",".join(f'"{item["link"]}"' for item in ready)

    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>إرسال كل التقارير لأولياء الأمور | منصة مدى</title>

<style>
* {{ box-sizing: border-box; }}

:root {{
    --primary: #2563eb;
    --primary-dark: #1d4ed8;
    --text: #0f172a;
    --muted: #64748b;
    --border: #e2e8f0;
    --bg: #f6f8fc;
    --card: #ffffff;
}}

body {{
    margin: 0;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
}}

a {{ color: inherit; }}

.container {{
    width: min(94%, 900px);
    margin: auto;
    padding: 26px 0 60px;
}}

.back-link {{
    display: inline-block;
    margin-bottom: 16px;
    color: var(--primary);
    text-decoration: none;
    font-weight: 700;
}}

.send-header {{
    background: linear-gradient(135deg, #1d4ed8, #2563eb 55%, #3b82f6);
    color: white;
    padding: 26px;
    border-radius: 20px;
    margin-bottom: 26px;
}}

.send-header h1 {{
    margin: 0 0 8px;
    font-size: 24px;
}}

.send-header p {{
    margin: 0 0 18px;
    opacity: .92;
    line-height: 1.8;
}}

.send-cta {{
    border: 0;
    background: #25D366;
    color: white;
    padding: 13px 22px;
    border-radius: 12px;
    cursor: pointer;
    font-weight: 700;
    font-size: 15px;
}}

.send-cta:hover {{ background: #1ebe5a; }}

#send-status {{
    margin: 12px 0 0;
    font-size: 13px;
    opacity: .95;
}}

.section-title {{
    font-size: 17px;
    margin: 24px 0 12px;
}}

.send-list {{
    display: flex;
    flex-direction: column;
    gap: 10px;
}}

.send-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 13px 18px;
}}

.send-row-missing {{ opacity: .7; }}

.send-info strong {{ display: block; font-size: 15px; }}
.send-info span {{ color: var(--muted); font-size: 12px; }}

.btn {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 9px 16px;
    border-radius: 10px;
    text-decoration: none;
    font-weight: 700;
    font-size: 13px;
    white-space: nowrap;
}}

.btn-whatsapp {{ background: #25D366; color: white; }}
.btn-whatsapp:hover {{ background: #1ebe5a; }}

.btn-disabled {{
    background: #eef2f7;
    color: var(--muted);
    cursor: not-allowed;
}}

.empty-note {{ color: var(--muted); }}
</style>
</head>

<body>
<div class="container">
    <a class="back-link" href="/">→ العودة للوحة التحكم</a>

    <div class="send-header">
        <h1>إرسال كل التقارير لأولياء الأمور</h1>
        <p>
            عدد الطلاب: {total} — جاهزون للإرسال عبر واتساب: {len(ready)}
            {f" — بدون رقم مسجل: {len(missing)}" if missing else ""}
            <br>
            سيفتح هذا الزر محادثة واتساب منفصلة لكل ولي أمر مع تقرير ابنه/ابنته
            جاهزًا كنص، وتضغط "إرسال" داخل كل محادثة بنفسك للتأكيد.
        </p>
        <button class="send-cta" onclick="openAllReports()">
            📤 فتح جميع محادثات أولياء الأمور ({len(ready)})
        </button>
        <p id="send-status"></p>
    </div>

    <h2 class="section-title">جاهزون للإرسال ({len(ready)})</h2>
    <div class="send-list">
        {ready_rows}
    </div>

    {missing_section}
</div>

<script>
const allLinks = [{links_js_array}];

function openAllReports() {{
    allLinks.forEach(function (link) {{
        window.open(link, "_blank", "noopener");
    }});

    const status = document.getElementById("send-status");

    if (allLinks.length === 0) {{
        status.textContent = "لا يوجد طلاب لديهم رقم واتساب صالح لولي الأمر.";
    }} else {{
        status.textContent =
            "تم فتح " + allLinks.length +
            " محادثة واتساب في نوافذ جديدة. إذا لم تظهر بعض النوافذ، " +
            "فعّل السماح بالنوافذ المنبثقة لهذا الموقع، أو استخدم الأزرار أدناه لكل ولي أمر على حدة.";
    }}
}}
</script>
</body>
</html>
"""


def _trend_svg(exam_1, exam_2):
    exam_1 = max(0, min(100, num(exam_1)))
    exam_2 = max(0, min(100, num(exam_2)))

    # Pure SVG so the app has no new frontend dependency.
    y1 = 125 - (exam_1 * 0.9)
    y2 = 125 - (exam_2 * 0.9)

    return f"""
    <svg viewBox="0 0 420 170" class="trend-svg" role="img"
         aria-label="تطور الأداء من الاختبار الأول إلى الاختبار الثاني">
        <line x1="45" y1="125" x2="390" y2="125"
              stroke="#e2e8f0" stroke-width="2"/>
        <line x1="45" y1="80" x2="390" y2="80"
              stroke="#eef2f7" stroke-width="1"/>
        <line x1="45" y1="35" x2="390" y2="35"
              stroke="#eef2f7" stroke-width="1"/>

        <polyline points="95,{y1:.1f} 325,{y2:.1f}"
                  fill="none" stroke="#2563eb"
                  stroke-width="5" stroke-linecap="round"/>

        <circle cx="95" cy="{y1:.1f}" r="8"
                fill="#ffffff" stroke="#2563eb" stroke-width="4"/>
        <circle cx="325" cy="{y2:.1f}" r="8"
                fill="#ffffff" stroke="#2563eb" stroke-width="4"/>

        <text x="95" y="155" text-anchor="middle"
              fill="#64748b" font-size="13">الاختبار الأول</text>
        <text x="325" y="155" text-anchor="middle"
              fill="#64748b" font-size="13">الاختبار الثاني</text>

        <text x="95" y="{max(22, y1 - 14):.1f}" text-anchor="middle"
              fill="#0f172a" font-size="14" font-weight="700">{exam_1:.0f}%</text>
        <text x="325" y="{max(22, y2 - 14):.1f}" text-anchor="middle"
              fill="#0f172a" font-size="14" font-weight="700">{exam_2:.0f}%</text>
    </svg>
    """


def dashboard_html():
    analyzed = [(student, analyze_student(student)) for student in current_students()]
    total = len(analyzed)

    # تحليل الفصل بالكامل (المرحلة 8 — Class Analytics)
    class_analysis = analyze_class(current_students())

    class_level_bars = class_level_distribution_html(
        class_analysis["level_distribution"]
    )

    class_gap_rows = class_gap_ranking_html(
        class_analysis["gap_ranking"],
        class_analysis["total_students"],
    )

    class_top_gap_alert = class_top_gap_alert_html(
        class_analysis["top_gap"],
        class_analysis["total_students"],
    )

    avg_score = (
        sum(num(s.get("score")) for s, _ in analyzed) / total
        if total else 0
    )

    avg_attendance = (
        sum(num(s.get("attendance_rate")) for s, _ in analyzed) / total
        if total else 0
    )

    top_students = sum(
        1 for s, _ in analyzed if num(s.get("score")) >= 85
    )

    support_students = sum(
        1 for s, _ in analyzed if num(s.get("score")) < 70
    )

    high_risk = sum(
        1 for _, ai in analyzed if ai["risk_level"] == "مرتفع"
    )

    # Average of the main performance components for the dashboard chart.
    component_names = [
        "الاختبارات",
        "الواجبات",
        "الاختبارات القصيرة",
        "المشاركة",
        "الحضور",
    ]

    component_values = {}
    for name in component_names:
        values = [
            num(ai["components"].get(name))
            for _, ai in analyzed
        ]
        component_values[name] = (
            sum(values) / len(values)
            if values else 0
        )

    component_bars = "".join(
        f"""
        <div class="chart-row">
            <div class="chart-meta">
                <span>{esc(name)}</span>
                <strong>{value:.1f}%</strong>
            </div>
            <div class="chart-track">
                <div class="chart-fill" style="width:{value:.1f}%"></div>
            </div>
        </div>
        """
        for name, value in component_values.items()
    )

    # Students are shown as compact, clickable summaries.
    cards = ""
    for student, ai in analyzed:
        score = num(student.get("score"))
        risk_class = (
            "risk-high" if ai["risk_level"] == "مرتفع"
            else "risk-medium" if ai["risk_level"] == "متوسط"
            else "risk-low"
        )

        whatsapp_link = build_whatsapp_share_link(student, ai)

        whatsapp_mini_html = (
            f"""
            <a href="{esc(whatsapp_link)}"
               class="small-whatsapp"
               target="_blank"
               rel="noopener noreferrer"
               onclick="event.stopPropagation()"
               title="إرسال التقرير لولي الأمر عبر واتساب">
                📲
            </a>
            """
            if whatsapp_link
            else """
            <span class="small-whatsapp small-whatsapp-disabled"
                  title="لا يوجد رقم واتساب لولي الأمر">
                📲
            </span>
            """
        )

        cards += f"""
        <article class="student-card"
                 onclick="window.location.href='/student/{esc(student['student_id'])}'"
                 tabindex="0"
                 onkeydown="if(event.key==='Enter') this.click()">

            <div class="student-card-head">
                <div class="student-avatar">
                    {esc(str(student.get("name", "ط")).strip()[:1])}
                </div>

                <div class="student-name-block">
                    <h3>{esc(student.get("name", "غير معروف"))}</h3>
                    <p>{esc(student.get("subject", "غير محدد"))}</p>
                </div>

                <div class="mini-score">
                    <strong>{score:.0f}%</strong>
                    <span>الدرجة</span>
                </div>
            </div>

            <div class="chips">
                <span class="chip">المستوى: {esc(ai["performance_level"])}</span>
                <span class="chip">الحضور: {num(student.get("attendance_rate")):.0f}%</span>
                <span class="chip {risk_class}">المخاطرة: {esc(ai["risk_level"])}</span>
            </div>

            <div class="student-preview-grid">
                <div>
                    <span>نقطة قوة</span>
                    <b>{esc(ai["strengths"][0])}</b>
                </div>
                <div>
                    <span>فجوة تعلم</span>
                    <b>{esc(ai["learning_gaps"][0])}</b>
                </div>
            </div>

            <div class="card-footer">
                <span class="details-link">عرض ملف الطالب ←</span>
                <a href="/student/{esc(student['student_id'])}/pdf"
                   class="small-pdf"
                   onclick="event.stopPropagation()">
                    PDF
                </a>
                {whatsapp_mini_html}
            </div>
        </article>
        """

    return f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>لوحة تحكم المدرس | منصة مدى</title>

<style>
* {{ box-sizing: border-box; }}

:root {{
    --primary: #2563eb;
    --primary-dark: #1d4ed8;
    --text: #0f172a;
    --muted: #64748b;
    --border: #e2e8f0;
    --bg: #f6f8fc;
    --card: #ffffff;
    --green: #16a34a;
    --orange: #d97706;
    --red: #dc2626;
}}

body {{
    margin: 0;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
}}

button, input {{ font: inherit; }}

a {{ color: inherit; }}

.container {{
    width: min(94%, 1450px);
    margin: auto;
}}

.hero {{
    background:
        radial-gradient(circle at 10% 20%, rgba(255,255,255,.18), transparent 30%),
        linear-gradient(135deg, #1d4ed8, #2563eb 55%, #3b82f6);
    color: white;
    padding: 30px 0 42px;
    border-radius: 0 0 30px 30px;
}}

.hero-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 24px;
}}

.brand h1 {{
    margin: 0 0 7px;
    font-size: clamp(26px, 3vw, 38px);
}}

.brand p {{
    margin: 0;
    opacity: .9;
    line-height: 1.8;
}}

.upload-box {{
    background: rgba(255,255,255,.97);
    color: var(--text);
    padding: 15px;
    border-radius: 18px;
    box-shadow: 0 18px 50px rgba(15,23,42,.16);
}}

.upload-form {{
    display: flex;
    gap: 9px;
    align-items: center;
}}

.upload-form input {{
    max-width: 220px;
}}

.primary-btn {{
    border: 0;
    background: var(--primary);
    color: white;
    padding: 11px 17px;
    border-radius: 11px;
    cursor: pointer;
    font-weight: 700;
}}

.hero-actions {{
    display: flex;
    flex-direction: column;
    gap: 10px;
    align-items: stretch;
}}

.send-all-cta {{
    display: inline-flex;
    justify-content: center;
    align-items: center;
    gap: 6px;
    background: #25D366;
    color: white;
    text-decoration: none;
    padding: 11px 17px;
    border-radius: 11px;
    font-weight: 700;
    white-space: nowrap;
}}

.send-all-cta:hover {{ background: #1ebe5a; }}

main {{ padding: 30px 0 60px; }}

.section-heading {{
    display: flex;
    justify-content: space-between;
    align-items: end;
    margin: 0 0 16px;
}}

.section-heading h2 {{
    margin: 0;
    font-size: 24px;
}}

.section-heading p {{
    margin: 5px 0 0;
    color: var(--muted);
}}

.kpis {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 14px;
    margin-top: -5px;
    margin-bottom: 28px;
}}

.kpi {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px;
    box-shadow: 0 7px 24px rgba(15,23,42,.05);
    min-height: 120px;
}}

.kpi-icon {{
    width: 38px;
    height: 38px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: #eff6ff;
    color: var(--primary);
    margin-bottom: 10px;
}}

.kpi-title {{
    color: var(--muted);
    font-size: 12px;
}}

.kpi-value {{
    font-size: 25px;
    font-weight: 800;
    margin-top: 4px;
}}

.dashboard-grid {{
    display: grid;
    grid-template-columns: 1.1fr .9fr;
    gap: 20px;
    margin-bottom: 28px;
}}

.panel {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 22px;
    padding: 22px;
    box-shadow: 0 7px 24px rgba(15,23,42,.05);
}}

.panel-title {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 18px;
}}

.panel-title h3 {{ margin: 0; font-size: 18px; }}
.panel-title span {{ color: var(--muted); font-size: 12px; }}

.chart-row {{ margin: 18px 0; }}

.chart-meta {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 7px;
    font-size: 13px;
}}

.chart-meta strong {{ color: var(--primary); }}

.chart-track {{
    height: 12px;
    background: #eaf0f7;
    border-radius: 999px;
    overflow: hidden;
}}

.chart-fill {{
    height: 100%;
    background: linear-gradient(90deg, #60a5fa, #2563eb);
    border-radius: inherit;
}}

.summary-list {{
    display: grid;
    gap: 12px;
}}

.summary-item {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 13px 14px;
    border-radius: 14px;
    background: #f8fafc;
}}

.summary-item span {{ color: var(--muted); font-size: 13px; }}
.summary-item strong {{ font-size: 16px; }}

/* ---------------------------------------------------- */
/* Class Analytics (المرحلة 8)                          */
/* ---------------------------------------------------- */

.class-avg-display {{
    text-align: center;
    background: linear-gradient(135deg, #eff6ff, #f8fafc);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 20px;
    margin-bottom: 22px;
}}

.class-avg-number {{
    font-size: 40px;
    font-weight: 800;
    color: var(--primary);
    line-height: 1.1;
}}

.class-avg-label {{
    color: var(--muted);
    font-size: 13px;
    margin-top: 6px;
}}

.level-row {{ margin: 16px 0; }}

.level-row-head {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 7px;
    font-size: 13px;
}}

.level-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex: 0 0 auto;
}}

.level-name {{ font-weight: 700; }}

.level-count {{ color: var(--muted); font-size: 12px; }}

.level-pct {{ margin-inline-start: auto; font-size: 15px; }}

.level-track {{
    height: 12px;
    background: #eaf0f7;
    border-radius: 999px;
    overflow: hidden;
}}

.level-fill {{
    height: 100%;
    border-radius: inherit;
    transition: width .3s ease;
}}

.level-excellent {{ background: var(--green); }}
.level-good {{ background: var(--primary); }}
.level-medium {{ background: var(--orange); }}
.level-support {{ background: var(--red); }}

.gap-alert {{
    display: flex;
    gap: 12px;
    align-items: flex-start;
    background: #fff7ed;
    border: 1px solid #fed7aa;
    border-radius: 16px;
    padding: 16px;
    margin-bottom: 18px;
}}

.gap-alert-icon {{ font-size: 20px; line-height: 1; }}

.gap-alert-body strong {{
    display: block;
    color: #9a3412;
    font-size: 14px;
    margin-bottom: 5px;
}}

.gap-alert-body p {{
    margin: 0;
    color: #7c2d12;
    font-size: 13px;
    line-height: 1.7;
}}

.gap-rank-list {{ display: grid; gap: 10px; }}

.gap-rank-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 12px 14px;
    border-radius: 14px;
    background: #f8fafc;
}}

.gap-rank-row.gap-rank-top {{
    background: #fff7ed;
    border: 1px solid #fed7aa;
}}

.gap-rank-left {{
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
}}

.gap-rank-number {{
    width: 24px;
    height: 24px;
    border-radius: 8px;
    background: var(--primary);
    color: white;
    font-size: 12px;
    font-weight: 800;
    display: grid;
    place-items: center;
    flex: 0 0 auto;
}}

.gap-rank-top .gap-rank-number {{ background: var(--orange); }}

.gap-rank-name {{
    font-size: 13px;
    font-weight: 700;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}

.gap-rank-right {{
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 0 0 auto;
}}

.gap-rank-track {{
    width: 70px;
    height: 8px;
    background: #e2e8f0;
    border-radius: 999px;
    overflow: hidden;
}}

.gap-rank-fill {{
    height: 100%;
    background: var(--orange);
    border-radius: inherit;
}}

.gap-rank-pct {{
    font-size: 12px;
    font-weight: 800;
    color: var(--orange);
    width: 34px;
    text-align: left;
}}

.gap-rank-count {{
    color: var(--muted);
    font-size: 11px;
    white-space: nowrap;
}}

@media (max-width: 600px) {{
    .gap-rank-row {{ flex-direction: column; align-items: stretch; }}
    .gap-rank-right {{ justify-content: space-between; }}
    .gap-rank-track {{ flex: 1; }}
}}

.students-toolbar {{
    display: flex;
    justify-content: space-between;
    gap: 14px;
    align-items: center;
    margin-bottom: 16px;
}}

.search {{
    width: min(360px, 100%);
    border: 1px solid var(--border);
    background: white;
    border-radius: 12px;
    padding: 11px 14px;
    outline: none;
}}

.search:focus {{
    border-color: #93c5fd;
    box-shadow: 0 0 0 4px #dbeafe;
}}

.students-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 18px;
}}

.student-card {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 20px;
    cursor: pointer;
    transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease;
}}

.student-card:hover,
.student-card:focus {{
    transform: translateY(-3px);
    border-color: #bfdbfe;
    box-shadow: 0 16px 35px rgba(37,99,235,.10);
    outline: none;
}}

.student-card-head {{
    display: grid;
    grid-template-columns: 48px 1fr auto;
    gap: 12px;
    align-items: center;
}}

.student-avatar {{
    width: 48px;
    height: 48px;
    border-radius: 15px;
    background: linear-gradient(135deg, #dbeafe, #eff6ff);
    color: var(--primary);
    display: grid;
    place-items: center;
    font-size: 20px;
    font-weight: 800;
}}

.student-name-block h3 {{ margin: 0; font-size: 18px; }}
.student-name-block p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}

.mini-score {{ text-align: left; }}
.mini-score strong {{ display: block; font-size: 22px; color: var(--primary); }}
.mini-score span {{ color: var(--muted); font-size: 11px; }}

.chips {{
    display: flex;
    flex-wrap: wrap;
    gap: 7px;
    margin: 17px 0;
}}

.chip {{
    padding: 7px 9px;
    border-radius: 9px;
    background: #f8fafc;
    color: #475569;
    font-size: 11px;
}}

.risk-high {{ background: #fef2f2; color: #b91c1c; }}
.risk-medium {{ background: #fff7ed; color: #c2410c; }}
.risk-low {{ background: #f0fdf4; color: #15803d; }}

.student-preview-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
}}

.student-preview-grid > div {{
    background: #f8fafc;
    border-radius: 13px;
    padding: 12px;
}}

.student-preview-grid span {{
    display: block;
    color: var(--muted);
    font-size: 11px;
    margin-bottom: 5px;
}}

.student-preview-grid b {{
    display: block;
    font-size: 12px;
    line-height: 1.6;
}}

.card-footer {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 17px;
    padding-top: 14px;
    border-top: 1px solid #eef2f7;
}}

.details-link {{
    color: var(--primary);
    font-weight: 700;
    font-size: 13px;
}}

.small-pdf {{
    background: #0f172a;
    color: white;
    text-decoration: none;
    padding: 7px 11px;
    border-radius: 8px;
    font-size: 11px;
}}

.small-whatsapp {{
    background: #25D366;
    color: white;
    text-decoration: none;
    padding: 7px 10px;
    border-radius: 8px;
    font-size: 13px;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}}

.small-whatsapp-disabled {{
    background: #e2e8f0;
    color: #94a3b8;
    cursor: not-allowed;
}}

.empty {{
    background: white;
    border: 1px dashed var(--border);
    border-radius: 18px;
    padding: 40px;
    text-align: center;
    color: var(--muted);
}}

@media (max-width: 1200px) {{
    .kpis {{ grid-template-columns: repeat(3, 1fr); }}
}}

@media (max-width: 900px) {{
    .dashboard-grid {{ grid-template-columns: 1fr; }}
    .students-grid {{ grid-template-columns: 1fr; }}
    .hero-top {{ flex-direction: column; align-items: stretch; }}
    .upload-form {{ flex-wrap: wrap; }}
}}

@media (max-width: 600px) {{
    .kpis {{ grid-template-columns: repeat(2, 1fr); }}
    .students-toolbar {{ align-items: stretch; flex-direction: column; }}
    .search {{ width: 100%; }}
    .student-preview-grid {{ grid-template-columns: 1fr; }}
}}

@media (max-width: 400px) {{
    .kpis {{ grid-template-columns: 1fr; }}
}}
</style>
</head>

<body>
<header class="hero">
    <div class="container hero-top">
        <div class="brand">
            <h1>منصة مدى التعليمية الذكية</h1>
            <p>مرحبًا {esc((current_teacher() or {}).get("name", "المعلم"))} — لوحة تحكمك التعليمية.</p>
        </div>

        <div class="upload-box hero-actions">
            <form class="upload-form" action="/upload" method="post"
                  enctype="multipart/form-data">
                <input type="file" name="file" accept=".csv" required>
                <button class="primary-btn" type="submit">رفع CSV</button>
            </form>

            <a class="send-all-cta" href="/send-all-reports">
                📤 إرسال كل التقارير لأولياء الأمور
            </a>
            <a href="/logout"
               style="display:inline-flex;justify-content:center;align-items:center;
                      background:#fff;color:#1d4ed8;text-decoration:none;
                      padding:10px 16px;border-radius:11px;font-weight:800;">
                تسجيل الخروج
            </a>
        </div>
    </div>
</header>

<main class="container">

    <div class="section-heading">
        <div>
            <h2>نظرة عامة</h2>
            <p>ملخص سريع يساعدك على اتخاذ قرار تعليمي أسرع.</p>
        </div>
    </div>

    <section class="kpis">
        <div class="kpi">
            <div class="kpi-icon">👥</div>
            <div class="kpi-title">إجمالي الطلاب</div>
            <div class="kpi-value">{total}</div>
        </div>

        <div class="kpi">
            <div class="kpi-icon">📈</div>
            <div class="kpi-title">متوسط الدرجات</div>
            <div class="kpi-value">{avg_score:.1f}%</div>
        </div>

        <div class="kpi">
            <div class="kpi-icon">🗓️</div>
            <div class="kpi-title">متوسط الحضور</div>
            <div class="kpi-value">{avg_attendance:.1f}%</div>
        </div>

        <div class="kpi">
            <div class="kpi-icon">🏆</div>
            <div class="kpi-title">الطلاب المتفوقون</div>
            <div class="kpi-value">{top_students}</div>
        </div>

        <div class="kpi">
            <div class="kpi-icon">🧭</div>
            <div class="kpi-title">يحتاجون دعم</div>
            <div class="kpi-value">{support_students}</div>
        </div>

        <div class="kpi">
            <div class="kpi-icon">⚠️</div>
            <div class="kpi-title">مخاطرة مرتفعة</div>
            <div class="kpi-value">{high_risk}</div>
        </div>
    </section>

    <section class="dashboard-grid">
        <div class="panel">
            <div class="panel-title">
                <h3>متوسط مؤشرات الأداء</h3>
                <span>على مستوى الفصل</span>
            </div>
            {component_bars}
        </div>

        <div class="panel">
            <div class="panel-title">
                <h3>ملخص القرار التعليمي</h3>
                <span>أولوية المتابعة</span>
            </div>

            <div class="summary-list">
                <div class="summary-item">
                    <span>متفوقون (85% فأعلى)</span>
                    <strong>{top_students}</strong>
                </div>
                <div class="summary-item">
                    <span>بحاجة إلى دعم (أقل من 70%)</span>
                    <strong>{support_students}</strong>
                </div>
                <div class="summary-item">
                    <span>مخاطرة مرتفعة</span>
                    <strong>{high_risk}</strong>
                </div>
                <div class="summary-item">
                    <span>متوسط الحضور</span>
                    <strong>{avg_attendance:.1f}%</strong>
                </div>
            </div>
        </div>
    </section>

    <div class="section-heading">
        <div>
            <h2>📈 تحليل الفصل</h2>
            <p>مش بس تحليل الطالب — هنا بنحلل الفصل كله لاتخاذ قرار تعليمي جماعي.</p>
        </div>
    </div>

    <section class="dashboard-grid class-analytics-grid">
        <div class="panel">
            <div class="panel-title">
                <h3>توزيع الأداء داخل الفصل</h3>
                <span>{class_analysis['total_students']} طالب</span>
            </div>

            <div class="class-avg-display">
                <div class="class-avg-number">{class_analysis['class_average']:.1f}%</div>
                <div class="class-avg-label">متوسط الفصل</div>
            </div>

            {class_level_bars}
        </div>

        <div class="panel">
            <div class="panel-title">
                <h3>أكثر المهارات التي يعاني منها الطلاب</h3>
                <span>مرتبة حسب عدد المتأثرين</span>
            </div>

            {class_top_gap_alert}

            <div class="gap-rank-list">
                {class_gap_rows}
            </div>
        </div>
    </section>

    <div class="students-toolbar">
        <div class="section-heading" style="margin:0">
            <div>
                <h2>الطلاب</h2>
                <p>اضغط على أي طالب لفتح ملفه التعليمي الكامل.</p>
            </div>
        </div>
        <input id="studentSearch" class="search"
               type="search"
               placeholder="ابحث باسم الطالب أو المادة..."
               oninput="filterStudents()">
    </div>

    <section id="studentsGrid" class="students-grid">
        {cards if cards else '<div class="empty">لا توجد بيانات طلاب حاليًا. ارفع ملف CSV للبدء.</div>'}
    </section>
</main>

<script>
function filterStudents() {{
    const q = document.getElementById("studentSearch").value.trim().toLowerCase();
    document.querySelectorAll(".student-card").forEach(card => {{
        const text = card.innerText.toLowerCase();
        card.style.display = text.includes(q) ? "" : "none";
    }});
}}
</script>
</body>
</html>
"""


def student_detail_html(student):
    ai = analyze_student(student)

    whatsapp_link = build_whatsapp_share_link(student, ai)

    if whatsapp_link:
        whatsapp_button_html = f"""
            <a class="btn btn-whatsapp"
               href="{esc(whatsapp_link)}"
               target="_blank"
               rel="noopener noreferrer">
                📲 إرسال التقرير لولي الأمر عبر واتساب
            </a>
        """
    else:
        whatsapp_button_html = """
            <span class="btn btn-whatsapp btn-disabled"
                  title="لا يوجد رقم هاتف مسجّل لولي الأمر">
                📲 لا يوجد رقم واتساب لولي الأمر
            </span>
        """

    score = num(student.get("score"))
    attendance = num(student.get("attendance_rate"))
    exam_1 = num(student.get("exam_1"), score)
    exam_2 = num(student.get("exam_2"), score)
    delta = exam_2 - exam_1

    if delta >= 5:
        trend_label = "تحسن واضح"
        trend_class = "trend-positive"
        trend_icon = "↗"
    elif delta <= -5:
        trend_label = "انخفاض يحتاج متابعة"
        trend_class = "trend-negative"
        trend_icon = "↘"
    else:
        trend_label = "الأداء مستقر"
        trend_class = "trend-neutral"
        trend_icon = "→"

    def detail_list(items, empty="لا توجد بيانات إضافية"):
        if not items:
            return f'<div class="empty-mini">{empty}</div>'
        return "".join(
            f'<li><span>✓</span><div>{esc(item)}</div></li>'
            for item in items
        )

    component_rows = "".join(
        f"""
        <div class="metric-row">
            <div class="metric-head">
                <span>{esc(label)}</span>
                <strong>{value:.0f}%</strong>
            </div>
            <div class="metric-track">
                <div class="metric-fill" style="width:{max(0,min(100,value)):.0f}%"></div>
            </div>
        </div>
        """
        for label, value in ai["components"].items()
    )

    return f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(student.get("name", "الطالب"))} | ملف الطالب</title>

<style>
* {{ box-sizing: border-box; }}

body {{
    margin: 0;
    background: #f6f8fc;
    color: #0f172a;
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
}}

.container {{
    width: min(94%, 1250px);
    margin: auto;
}}

.topbar {{
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    color: white;
    padding: 18px 0;
}}

.topbar-inner {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
}}

.back {{
    color: white;
    text-decoration: none;
    background: rgba(255,255,255,.13);
    border: 1px solid rgba(255,255,255,.2);
    padding: 9px 13px;
    border-radius: 10px;
}}

.page {{ padding: 28px 0 60px; }}

.profile {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 24px;
    padding: 24px;
    display: grid;
    grid-template-columns: auto 1fr auto;
    gap: 20px;
    align-items: center;
    box-shadow: 0 8px 28px rgba(15,23,42,.06);
}}

.avatar {{
    width: 76px;
    height: 76px;
    border-radius: 22px;
    display: grid;
    place-items: center;
    background: #dbeafe;
    color: #1d4ed8;
    font-size: 30px;
    font-weight: 800;
}}

.profile h1 {{ margin: 0 0 5px; font-size: 28px; }}
.profile p {{ margin: 0; color: #64748b; }}

.profile-actions {{
    display: flex;
    gap: 9px;
    flex-wrap: wrap;
    justify-content: flex-end;
}}

.btn {{
    display: inline-block;
    text-decoration: none;
    border-radius: 10px;
    padding: 10px 14px;
    font-weight: 700;
}}

.btn-primary {{ background: #2563eb; color: white; }}
.btn-dark {{ background: #0f172a; color: white; }}
.btn-whatsapp {{ background: #25D366; color: white; }}
.btn-whatsapp:hover {{ background: #1ebe5a; }}
.btn-disabled {{
    background: #e2e8f0;
    color: #94a3b8;
    cursor: not-allowed;
}}

.kpis {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin: 18px 0;
}}

.kpi {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 18px;
    padding: 18px;
}}

.kpi span {{ color: #64748b; font-size: 12px; }}
.kpi strong {{ display:block; margin-top:5px; font-size:25px; }}

.grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
}}

.card {{
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 20px;
    padding: 22px;
    box-shadow: 0 7px 24px rgba(15,23,42,.04);
}}

.card.full {{ grid-column: 1 / -1; }}

.card h2 {{
    margin: 0 0 16px;
    font-size: 19px;
}}

.muted {{ color: #64748b; }}

.metrics {{ display: grid; gap: 13px; }}

.metric-head {{
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    margin-bottom: 6px;
}}

.metric-head strong {{ color: #2563eb; }}

.metric-track {{
    height: 10px;
    background: #eaf0f7;
    border-radius: 999px;
    overflow: hidden;
}}

.metric-fill {{
    height: 100%;
    background: linear-gradient(90deg,#60a5fa,#2563eb);
    border-radius: inherit;
}}

.trend-box {{
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 15px;
    align-items: center;
}}

.trend-svg {{ width: 100%; max-width: 500px; }}

.trend-badge {{
    min-width: 150px;
    border-radius: 16px;
    padding: 17px;
    text-align: center;
}}

.trend-badge strong {{
    display: block;
    font-size: 28px;
    margin-bottom: 4px;
}}

.trend-positive {{ background: #f0fdf4; color: #15803d; }}
.trend-negative {{ background: #fef2f2; color: #b91c1c; }}
.trend-neutral {{ background: #f8fafc; color: #475569; }}

.list {{
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 10px;
}}

.list li {{
    display: flex;
    gap: 10px;
    align-items: flex-start;
    background: #f8fafc;
    padding: 11px 12px;
    border-radius: 12px;
    line-height: 1.7;
    font-size: 13px;
}}

.list li > span {{
    color: #2563eb;
    font-weight: 800;
}}

.strength li {{ background:#f0fdf4; }}
.strength li > span {{ color:#15803d; }}

.weakness li {{ background:#fff7ed; }}
.weakness li > span {{ color:#c2410c; }}

.gap li {{ background:#fff7ed; }}
.gap li > span {{ color:#ea580c; }}

.plan-card {{
    background: #f8fafc;
    border-radius: 15px;
    padding: 15px;
}}

.plan-card h3 {{ margin: 0 0 11px; font-size: 15px; }}

.recommendation {{
    background: #eff6ff;
    border-right: 5px solid #2563eb;
    border-radius: 14px;
    padding: 18px;
    line-height: 1.9;
}}

.goal {{
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: 15px;
    padding: 18px;
    line-height: 1.9;
}}

.info-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
}}

.info {{
    background: #f8fafc;
    border-radius: 12px;
    padding: 12px;
}}

.info span {{
    display:block;
    color:#64748b;
    font-size:11px;
    margin-bottom:4px;
}}

.info strong {{ font-size:13px; }}

.book {{
    display:flex;
    justify-content:space-between;
    gap:10px;
    align-items:center;
    padding:13px;
    background:#f8fafc;
    border-radius:13px;
}}

.empty-mini {{ color:#64748b; padding:12px; }}

.table-wrap {{ overflow-x: auto; }}

.weekly-plan-table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0 8px;
    min-width: 480px;
}}

.weekly-plan-table thead th {{
    text-align: right;
    font-size: 12px;
    color: #64748b;
    font-weight: 700;
    padding: 0 14px 6px;
}}

.weekly-plan-table thead th:first-child {{ width: 90px; text-align:center; }}
.weekly-plan-table thead th:last-child {{ width: 110px; text-align:center; }}

.weekly-plan-table tbody tr {{
    background: #f8fafc;
}}

.weekly-plan-table td {{
    padding: 13px 14px;
    font-size: 13px;
    color: #334155;
    line-height: 1.6;
}}

.weekly-plan-table td:first-child {{
    border-radius: 12px 0 0 12px;
}}

.weekly-plan-table td:last-child {{
    border-radius: 0 12px 12px 0;
}}

.weekly-plan-table .wp-day {{
    font-weight: 800;
    color: #0f172a;
    text-align: center;
    white-space: nowrap;
}}

.weekly-plan-table .wp-task {{ font-weight: 500; }}

.wp-tag {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
}}

.wp-learn      {{ background:#eff6ff; color:#1d4ed8; }}
.wp-practice   {{ background:#f0fdf4; color:#15803d; }}
.wp-assess     {{ background:#fef2f2; color:#b91c1c; }}
.wp-review     {{ background:#fff7ed; color:#c2410c; }}
.wp-foundation {{ background:#f5f3ff; color:#6d28d9; }}
.wp-challenge  {{ background:#ecfeff; color:#0e7490; }}
.wp-followup   {{ background:#fdf4ff; color:#a21caf; }}

@media(max-width:550px) {{
    .weekly-plan-table {{ min-width: 420px; }}
}}

@media(max-width:900px) {{
    .profile {{ grid-template-columns: auto 1fr; }}
    .profile-actions {{ grid-column: 1 / -1; justify-content: flex-start; }}
    .grid {{ grid-template-columns: 1fr; }}
    .card.full {{ grid-column: auto; }}
    .kpis {{ grid-template-columns: repeat(2, 1fr); }}
    .trend-box {{ grid-template-columns: 1fr; }}
}}

@media(max-width:550px) {{
    .kpis {{ grid-template-columns: 1fr; }}
    .profile {{ grid-template-columns: 1fr; text-align:center; }}
    .avatar {{ margin:auto; }}
    .profile-actions {{ justify-content:center; }}
    .info-grid {{ grid-template-columns:1fr; }}
}}
</style>
</head>

<body>
<header class="topbar">
    <div class="container topbar-inner">
        <strong>منصة مدى التعليمية الذكية</strong>
        <a class="back" href="/">← العودة للوحة التحكم</a>
    </div>
</header>

<main class="container page">

    <section class="profile">
        <div class="avatar">{esc(str(student.get("name", "ط")).strip()[:1])}</div>

        <div>
            <h1>{esc(student.get("name", "غير معروف"))}</h1>
            <p>{esc(student.get("subject", "غير محدد"))} · رقم الطالب {esc(student.get("student_id", "-"))}</p>
        </div>

        <div class="profile-actions">
            <a class="btn btn-primary"
               href="/student/{esc(student.get('student_id'))}/pdf">
                📄 تحميل تقرير PDF
            </a>
            {whatsapp_button_html}
            <a class="btn btn-dark" href="/">لوحة التحكم</a>
        </div>
    </section>

    <section class="kpis">
        <div class="kpi">
            <span>الأداء الحالي</span>
            <strong>{score:.0f}%</strong>
        </div>
        <div class="kpi">
            <span>الحضور</span>
            <strong>{attendance:.0f}%</strong>
        </div>
        <div class="kpi">
            <span>المستوى</span>
            <strong>{esc(ai["performance_level"])}</strong>
        </div>
        <div class="kpi">
            <span>المخاطرة</span>
            <strong>{esc(ai["risk_level"])}</strong>
        </div>
    </section>

    <div class="grid">

        <section class="card">
            <h2>معلومات الطالب</h2>
            <div class="info-grid">
                <div class="info"><span>الاسم</span><strong>{esc(student.get("name"))}</strong></div>
                <div class="info"><span>رقم الطالب</span><strong>{esc(student.get("student_id"))}</strong></div>
                <div class="info"><span>المادة</span><strong>{esc(student.get("subject"))}</strong></div>
                <div class="info"><span>الدرجة الموزونة</span><strong>{ai["weighted_score"]:.1f}%</strong></div>
                <div class="info"><span>الاختبار الأول</span><strong>{exam_1:.0f}%</strong></div>
                <div class="info"><span>الاختبار الثاني</span><strong>{exam_2:.0f}%</strong></div>
            </div>
        </section>

        <section class="card">
            <h2>الأداء الحالي</h2>
            <div class="metrics">
                {component_rows}
            </div>
        </section>

        <section class="card full">
            <h2>تطور الأداء</h2>
            <div class="trend-box">
                {_trend_svg(exam_1, exam_2)}
                <div class="trend-badge {trend_class}">
                    <strong>{trend_icon} {delta:+.1f}</strong>
                    <span>{trend_label}</span>
                </div>
            </div>
        </section>

        <section class="card">
            <h2>نقاط القوة</h2>
            <ul class="list strength">
                {detail_list(ai["strengths"])}
            </ul>
        </section>

        <section class="card">
            <h2>نقاط الضعف</h2>
            <ul class="list weakness">
                {detail_list(ai["weaknesses"])}
            </ul>
        </section>

        <section class="card full">
            <h2>فجوات التعلم</h2>
            <ul class="list gap">
                {detail_list(ai["learning_gaps"])}
            </ul>
        </section>

        <section class="card full">
            <h2>التوصية الشخصية</h2>
            <div class="recommendation">{esc(ai["recommendation"])}</div>
        </section>

        <section class="card">
            <h2>خطة المدرس</h2>
            <div class="plan-card">
                <ul class="list">
                    {detail_list(ai["teacher_actions"])}
                </ul>
            </div>
        </section>

        <section class="card">
            <h2>خطة الطالب</h2>
            <div class="plan-card">
                <ul class="list">
                    {detail_list(ai["student_plan"])}
                </ul>
            </div>
        </section>

        <section class="card">
            <h2>دور ولي الأمر</h2>
            <div class="plan-card">
                <ul class="list">
                    {detail_list(ai["parent_actions"])}
                </ul>
            </div>
        </section>

        <section class="card">
            <h2>الهدف الأسبوعي</h2>
            <div class="goal">🎯 {esc(ai["weekly_goal"])}</div>
        </section>

        <section class="card full">
            <h2>خطة التعلم الأسبوعية</h2>
            {weekly_plan_table_html(ai["weekly_plan"])}
        </section>

        <section class="card full">
            <h2>المصدر التعليمي المقترح</h2>
            <div class="book">
                <span>{esc(ai["suggested_book"])}</span>
                <span class="muted">{esc(student.get("subject", ""))}</span>
            </div>
        </section>

    </div>
</main>
</body>
</html>
"""


# =========================================================
# AUTH ROUTES
# =========================================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_teacher(request):
        return RedirectResponse("/", status_code=303)
    return auth_form_html("login")


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    teacher = teachers_collection.find_one({"email": email})

    if not teacher or not verify_password(password, teacher.get("password_hash", "")):
        return auth_form_html(
            "login",
            "البريد الإلكتروني أو كلمة المرور غير صحيحة."
        )

    token = create_session(teacher["_id"])
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "mada_session",
        token,
        max_age=SESSION_DAYS * 24 * 60 * 60,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return response


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if get_teacher(request):
        return RedirectResponse("/", status_code=303)
    return auth_form_html("signup")


@app.post("/signup", response_class=HTMLResponse)
def signup(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    name = name.strip()
    email = email.strip().lower()

    if len(name) < 2:
        return auth_form_html("signup", "اكتب اسم المعلم بشكل صحيح.")

    if len(password) < 6:
        return auth_form_html(
            "signup",
            "كلمة المرور يجب أن تكون 6 أحرف على الأقل."
        )

    teacher_doc = {
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "created_at": datetime.utcnow(),
    }

    try:
        result = teachers_collection.insert_one(teacher_doc)
    except DuplicateKeyError:
        return auth_form_html(
            "signup",
            "هذا البريد الإلكتروني مسجل بالفعل. جرّب تسجيل الدخول."
        )

    teacher_id = str(result.inserted_id)

    # يبدأ المعلم ببيانات تجريبية يمكن استبدالها لاحقًا بملف CSV.
    save_teacher_students(teacher_id, students_data)

    token = create_session(teacher_id)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "mada_session",
        token,
        max_age=SESSION_DAYS * 24 * 60 * 60,
        httponly=True,
        samesite="lax",
        secure=False,
    )
    return response


@app.get("/logout")
def logout(request: Request):
    token = request.cookies.get("mada_session")
    if token:
        sessions_collection.delete_one({"token": token})

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("mada_session")
    return response


# =========================================================
# HOME
# =========================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def home(request: Request):

    teacher, redirect = require_teacher(request)
    if redirect:
        return redirect

    set_teacher_context(teacher)
    set_students_context(load_teacher_students(teacher["id"]))
    return dashboard_html()


# =========================================================
# SEND ALL REPORTS TO PARENTS (WhatsApp, bulk)
# =========================================================

@app.get(
    "/send-all-reports",
    response_class=HTMLResponse
)
def send_all_reports(request: Request):

    teacher, redirect = require_teacher(request)
    if redirect:
        return redirect

    set_teacher_context(teacher)
    set_students_context(load_teacher_students(teacher["id"]))
    return send_all_reports_html()


# =========================================================
# STUDENT DETAILS
# =========================================================

@app.get(
    "/student/{student_id}",
    response_class=HTMLResponse
)
def student_details(request: Request, student_id: str):
    teacher, redirect = require_teacher(request)
    if redirect:
        return redirect

    set_teacher_context(teacher)
    set_students_context(load_teacher_students(teacher["id"]))
    student = _find_student(student_id)

    if student is None:
        return HTMLResponse(
            """
            <html lang="ar" dir="rtl">
            <body style="font-family:Arial;padding:40px">
                <h2>الطالب غير موجود</h2>
                <a href="/">العودة للوحة التحكم</a>
            </body>
            </html>
            """,
            status_code=404
        )

    return student_detail_html(student)


# =========================================================
# UPLOAD CSV
# =========================================================

@app.post(
    "/upload",
    response_class=HTMLResponse
)
async def upload_csv(
    request: Request,
    file: UploadFile = File(...)
):

    teacher, redirect = require_teacher(request)
    if redirect:
        return redirect

    try:

        content = await file.read()

        df = pd.read_csv(
            BytesIO(content)
        )

        required_columns = [
            "student_id",
            "name",
            "subject",
            "score",
            "attendance_rate",
        ]

        missing = [
            col
            for col in required_columns
            if col not in df.columns
        ]

        if missing:

            return HTMLResponse(
                f"""
                <h2>
                خطأ في ملف CSV
                </h2>

                <p>
                الأعمدة الناقصة:
                {", ".join(missing)}
                </p>

                <a href="/">
                العودة
                </a>
                """,
                status_code=400
            )

        # Fill optional numeric columns

        optional_columns = [
            "exam_1",
            "exam_2",
            "homework",
            "quiz",
            "participation",
        ]

        for column in optional_columns:

            if column not in df.columns:

                df[column] = df["score"]

        # Optional column: parent WhatsApp number (not a score,
        # so it's filled with an empty string instead of df["score"]).

        if "parent_phone" not in df.columns:

            df["parent_phone"] = ""

        df = df.fillna(0)

        # fillna(0) above would turn a missing parent_phone into the
        # number 0, so restore it to an empty string afterward.
        df["parent_phone"] = df["parent_phone"].replace(0, "").astype(str)
        df.loc[df["parent_phone"] == "0", "parent_phone"] = ""

        uploaded_students = (
            df.to_dict(
                orient="records"
            )
        )

        save_teacher_students(teacher["id"], uploaded_students)
        set_students_context(uploaded_students)

        return dashboard_html()

    except Exception as e:

        return HTMLResponse(
            f"""
            <h2>
            حدث خطأ أثناء قراءة الملف
            </h2>

            <p>
            {esc(e)}
            </p>

            <a href="/">
            العودة للمنصة
            </a>
            """,
            status_code=400
        )


# =========================================================
# STUDENT PDF
# =========================================================

@app.get(
    "/student/{student_id}/pdf"
)
def student_pdf(
    request: Request,
    student_id: str
):

    teacher, redirect = require_teacher(request)
    if redirect:
        return redirect

    teacher_students = load_teacher_students(teacher["id"])
    set_teacher_context(teacher)
    set_students_context(teacher_students)

    student = None

    for item in teacher_students:

        if str(
            item.get("student_id")
        ) == str(student_id):

            student = item
            break

    if student is None:

        return HTMLResponse(
            "<h2>الطالب غير موجود</h2>",
            status_code=404
        )

    pdf_buffer = create_student_pdf(
        student
    )

    filename = (
        f"student_{student_id}_report.pdf"
    )

    return StreamingResponse(

        pdf_buffer,

        media_type="application/pdf",

        headers={
            "Content-Disposition":
                f'attachment; filename="{filename}"'
        }
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )
