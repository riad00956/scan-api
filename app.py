import os
import uuid
import threading
from flask import Flask, request, jsonify
from ddos import WebsiteGrandMasterPro

app = Flask(__name__)

# কনফিগারেশন (Railway এনভায়রনমেন্ট ভেরিয়েবল)
API_PASSWORD = os.environ.get('API_PASSWORD', 'adminpass')
is_enabled = True
scan_lock = threading.Lock()
tasks = {}  # {task_id: {'status': 'running'/'done', 'result': {}, 'error': None}}

@app.route('/status', methods=['GET'])
def status():
    """
    API চালু/বন্ধ নিয়ন্ত্রণ।
    ব্যবহার: /status?action=on&pass=yourpass
            /status?action=off&pass=yourpass
            /status?pass=yourpass   (বর্তমান অবস্থা দেখায়)
    """
    password = request.args.get('pass')
    if password != API_PASSWORD:
        return jsonify({'error': 'Invalid password'}), 401

    action = request.args.get('action')
    global is_enabled
    if action == 'on':
        is_enabled = True
        return jsonify({'status': 'enabled'})
    elif action == 'off':
        is_enabled = False
        return jsonify({'status': 'disabled'})
    else:
        return jsonify({'enabled': is_enabled})

@app.route('/scan', methods=['GET'])
def scan():
    """
    স্ক্যান শুরু করার এন্ডপয়েন্ট।
    ব্যবহার: /scan?target=example.com
    রিটার্ন: {'task_id': '...'}
    """
    if not is_enabled:
        return jsonify({'error': 'API is disabled'}), 403

    target = request.args.get('target')
    if not target:
        return jsonify({'error': 'Missing target parameter'}), 400

    # স্ক্যান চলছে কিনা চেক (ঐচ্ছিক)
    with scan_lock:
        # একসাথে একাধিক স্ক্যান চালানোর অনুমতি দিতে চাইলে এই লুপ সরিয়ে ফেলুন
        for tid, t in tasks.items():
            if t['status'] == 'running':
                return jsonify({'error': 'A scan is already running. Please wait.'}), 409

        task_id = str(uuid.uuid4())
        tasks[task_id] = {'status': 'running', 'result': None, 'error': None}

    # ব্যাকগ্রাউন্ড থ্রেডে স্ক্যান চালান
    def run_scanner():
        try:
            scanner = WebsiteGrandMasterPro(
                target=target,
                timeout=5,
                threads=10,
                wordlist=None,
                output_json=None
            )
            scanner.run_scan()
            tasks[task_id]['result'] = scanner.results
            tasks[task_id]['status'] = 'done'
        except Exception as e:
            tasks[task_id]['error'] = str(e)
            tasks[task_id]['status'] = 'error'

    thread = threading.Thread(target=run_scanner)
    thread.daemon = True
    thread.start()

    return jsonify({'task_id': task_id})

@app.route('/result/<task_id>', methods=['GET'])
def result(task_id):
    """
    স্ক্যানের ফলাফল পাওয়ার এন্ডপয়েন্ট।
    রিটার্ন: {'status': 'running'/'done'/'error', 'result': {...}, 'error': '...'}
    """
    task = tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    if task['status'] == 'done':
        return jsonify({'status': 'done', 'result': task['result']})
    elif task['status'] == 'error':
        return jsonify({'status': 'error', 'error': task['error']})
    else:
        return jsonify({'status': 'running'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
