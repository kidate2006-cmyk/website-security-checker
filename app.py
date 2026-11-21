

from flask import Flask, render_template, request
from flask import send_file
from urllib.parse import urlparse
import ssl
import socket
import certifi
from datetime import datetime, timezone
import requests
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import json
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
# 日本語フォントを登録する
pdfmetrics.registerFont(UnicodeCIDFont("HeiseiMin-W3"))

app = Flask(__name__)

def draw_wrapped_text(pdf, text, x, y, max_width, font_size=11):

    pdf.setFont("HeiseiMin-W3", font_size)

    # 文章を1行ずつに分割する
    lines = []
    current_line = ""

    for char in str(text):
        test_line = current_line + char

        if pdf.stringWidth(
            test_line, "HeiseiMin-W3", font_size
        ) <= max_width:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = char

    if current_line:
        lines.append(current_line)

    # 分割した文章をPDFに表示する
    for line in lines:

        # ページ下端に近づいたら次のページへ
        if y < 50:
            pdf.showPage()
            pdf.setFont("HeiseiMin-W3", font_size)
            y = 790

        pdf.drawString(x, y, line)
        y -= font_size + 6

    return y


def create_pdf(url, checked_at, result, remaining_days,
               expiry_status, header_results,
               configured_count, total_headers, evaluation):

    # PDFをメモリ上に作成する
    buffer = BytesIO()

    # A4サイズのPDFを作成する
    pdf = canvas.Canvas(buffer, pagesize=A4)

    width, height = A4

    # タイトル
    pdf.setFont("HeiseiMin-W3", 18)
    pdf.drawString(50, height - 50, "セキュリティ診断レポート")

    y = height - 90

    # 診断対象と日時
    y = draw_wrapped_text(
        pdf, f"診断対象：{url}", 50, y, 490
    )

    y = draw_wrapped_text(
        pdf, f"診断日時：{checked_at}", 50, y - 5, 490
    )

    # SSL/TLS証明書診断
    y -= 20

    if y < 100:
        pdf.showPage()
        y = height - 50

    pdf.setFont("HeiseiMin-W3", 14)
    pdf.drawString(50, y, "SSL/TLS証明書診断")
    y -= 25

    y = draw_wrapped_text(
        pdf, f"診断結果：{result}", 50, y, 490
    )

    y = draw_wrapped_text(
        pdf, f"残り有効日数：{remaining_days}", 50, y - 5, 490
    )

    y = draw_wrapped_text(
        pdf, f"判定：{expiry_status}", 50, y, 490
    )

    # HTTPセキュリティヘッダー診断
    y -= 20

    if y < 100:
        pdf.showPage()
        y = height - 50

    pdf.setFont("HeiseiMin-W3", 14)
    pdf.drawString(50, y, "HTTPセキュリティヘッダー診断")
    y -= 25

    y = draw_wrapped_text(
        pdf,
        f"設定項目数：{configured_count} / {total_headers}",
        50, y, 490
    )

    y = draw_wrapped_text(
        pdf,
        f"総合評価：{evaluation}",
        50, y - 5, 490
    )

    y -= 10

    # 各ヘッダーの診断結果
    for item in header_results:

        y = draw_wrapped_text(
            pdf,
            f"{item['name']}：{item['status']}",
            50, y, 490
        )

        y -= 10

    # PDFを完成させる
    pdf.save()

    # PDFデータを先頭に戻す
    buffer.seek(0)

    return buffer

   
@app.route("/download", methods=["POST"])
def download():

    # フォームから診断結果を取得する
    url = request.form.get("url")
    checked_at = request.form.get("checked_at")
    result = request.form.get("result")
    remaining_days = request.form.get("remaining_days")
    expiry_status = request.form.get("expiry_status")
    header_results = json.loads(
        request.form.get("header_results", "[]")
    )
    configured_count = request.form.get("configured_count")
    total_headers = request.form.get("total_headers")
    evaluation = request.form.get("evaluation")

    # PDFを作成する
    pdf_buffer = create_pdf(
        url,
        checked_at,
        result,
        remaining_days,
        expiry_status,
        header_results,
        configured_count,
        total_headers,
        evaluation
    )

    # PDFをダウンロードさせる
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="security_report.pdf",
        mimetype="application/pdf"
    )
@app.route("/")
def index():
    return render_template("index.html")
# セキュリティヘッダーの解説ページ
@app.route("/guide/<page>")
def guide(page):

    guide_pages = [
        "hsts",
        "csp",
        "nosniff",
        "xframe",
        "referrer"
    ]

    if page not in guide_pages:
        return "ページが見つかりません", 404

    return render_template(f"guides/{page}.html")

@app.route("/check", methods=["POST"])
def check():

    # フォームからURLを取得する
    url = request.form.get("url", "").strip()

    # 診断日時を取得する
    checked_at = datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")

    # URLが入力されているか確認する
    if not url:
        return render_template(
            "result.html",
            url="未入力",
            checked_at=checked_at,
            result="URLが入力されていません。URLを入力してください。",
            header_results=[],
            configured_count=0,
            total_headers=5,
            evaluation="評価できません",
            remaining_days=None,
            expiry_status="評価できません",
            missing_headers=[]
        )

    # URLを解析する
    parsed_url = urlparse(url)

    # HTTPS形式か確認する
    if parsed_url.scheme.lower() != "https":
        return render_template(
            "result.html",
            url=url,
            checked_at=checked_at,
            result="HTTPS形式のURLを入力してください。",
            header_results=[],
            configured_count=0,
            total_headers=5,
            evaluation="評価できません",
            remaining_days=None,
            expiry_status="評価できません",
            missing_headers=[]
        )

    hostname = parsed_url.hostname

    # ポート番号を取得する
    try:
        port = parsed_url.port
    except ValueError:
        return render_template(
            "result.html",
            url=url,
            checked_at=checked_at,
            result="URLのポート番号が正しくありません。",
            header_results=[],
            configured_count=0,
            total_headers=5,
            evaluation="評価できません",
            remaining_days=None,
            expiry_status="評価できません",
            missing_headers=[]
        )

    # 診断対象を確認する
    if (
        hostname != "example.com"
        or port not in (None, 443)
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        return render_template(
            "result.html",
            url=url,
            checked_at=checked_at,
            result="現在は example.com のみ診断できます。",
            header_results=[],
            configured_count=0,
            total_headers=5,
            evaluation="評価できません",
            remaining_days=None,
            expiry_status="評価できません",
            missing_headers=[]
        )

    # エラーが発生した場合に備えて初期値を設定する
    header_results = []
    configured_count = 0
    total_headers = 5
    evaluation = "評価できません"
    remaining_days = None
    expiry_status = "評価できません"
    missing_headers = []

    try:
        # SSL/TLS証明書を確認する
        context = ssl.create_default_context(
            cafile=certifi.where()
        )

        with socket.create_connection(
            (hostname, 443), timeout=5
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as secure_sock:

                cert = secure_sock.getpeercert()

        # 証明書の情報を取得する
        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])

        issuer_name = issuer.get("organizationName", "不明")
        subject_name = subject.get("commonName", "不明")

        expiry = datetime.strptime(
            cert["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )

        # 証明書の有効期限をUTCとして扱う
        expiry = expiry.replace(tzinfo=timezone.utc)

        # 現在時刻を取得する
        now = datetime.now(timezone.utc)

        # 有効期限までの残り日数を計算する
        remaining_days = (expiry - now).days

        # 残り日数に応じて状態を判定する
        if remaining_days < 0:
            expiry_status = "期限切れ"
        elif remaining_days < 30:
            expiry_status = "早めの更新が必要"
        elif remaining_days < 90:
            expiry_status = "有効期限が近づいています"
        else:
            expiry_status = "有効"

        result = (
            f"HTTPS接続に成功しました。"
            f"発行先：{subject_name} / "
            f"発行者：{issuer_name} / "
            f"有効期限：{expiry.strftime('%Y年%m月%d日')}"
        )

        # HTTPレスポンスを取得する
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            verify=certifi.where()
        )

        # HTTPレスポンスヘッダーを取得する
        headers = response.headers

        # 確認するセキュリティヘッダー
        security_headers = {
            "Strict-Transport-Security": "HTTPSを強制する設定",
            "Content-Security-Policy": "読み込むコンテンツを制限する設定",
            "X-Content-Type-Options": "ファイル形式の誤認を防ぐ設定",
            "X-Frame-Options": "他サイトからの不正な埋め込みを防ぐ設定",
            "Referrer-Policy": "参照元情報を制御する設定"
        }

        # 診断結果を保存するリスト
        header_results = []

        # 1つずつヘッダーを確認する
        for header, description in security_headers.items():

            value = headers.get(header)

            if value:
                status = "設定あり"
            else:
                status = "未設定"

            header_results.append({
                "name": header,
                "description": description,
                "status": status,
                "value": value
            })

        # 設定されているヘッダーの数を集計する
        configured_count = sum(
            1 for item in header_results
            if item["status"] == "設定あり"
        )

        # 未設定のヘッダーを抽出する
        missing_headers = [
            item for item in header_results
            if item["status"] == "未設定"
        ]

        # 確認したヘッダーの総数
        total_headers = len(header_results)

        # 設定数に応じて総合評価を決める
        if configured_count >= 4:
            evaluation = "設定状況は良好"
        elif configured_count >= 2:
            evaluation = "改善の余地あり"
        else:
            evaluation = "設定の見直しを推奨"

    except ssl.SSLCertVerificationError:
        result = "SSL証明書の検証に失敗しました。証明書の有効性を確認してください。"
        expiry_status = "評価できません"

    except ssl.SSLError:
        result = "SSL/TLS通信でエラーが発生しました。"
        expiry_status = "評価できません"

    except socket.timeout:
        result = "接続がタイムアウトしました。時間をおいて再度お試しください。"
        expiry_status = "評価できません"

    except socket.gaierror:
        result = "ホスト名を解決できませんでした。接続状況を確認してください。"
        expiry_status = "評価できません"

    except requests.exceptions.Timeout:
        result = "Webサイトへの接続がタイムアウトしました。"
        expiry_status = "評価できません"

    except requests.exceptions.RequestException:
        result = "Webサイトへのリクエストに失敗しました。接続状況を確認してください。"
        expiry_status = "評価できません"

    except Exception:
        result = "予期しないエラーが発生しました。時間をおいて再度お試しください。"
        expiry_status = "評価できません"

    return render_template(
        "result.html",
        url=url,
        checked_at=checked_at,
        result=result,
        header_results=header_results,
        configured_count=configured_count,
        total_headers=total_headers,
        evaluation=evaluation,
        remaining_days=remaining_days,
        expiry_status=expiry_status,
        missing_headers=missing_headers
    )

if __name__ == "__main__":
    app.run(debug=True)    
  
       