from flask import Flask, request, jsonify, render_template
import hashlib
import random
import string
import json
from threading import Thread
import queue
import time
import itertools
import os
import ctypes
from multiprocessing import Value

app = Flask(__name__)

# Vercel için multiprocessing desteğini kontrol et
IS_VERCEL = os.environ.get('VERCEL')

if IS_VERCEL:
    from threading import Thread as Process
    from queue import Queue as MultiQueue
    cpu_count = lambda: 4
else:
    from multiprocessing import Process, Queue as MultiQueue, cpu_count

# ===== GLOBAL DEĞİŞKENLER =====
progress_queue = queue.Queue()
current_password = None
is_cracking = False
multi_progress_queue = MultiQueue()
multi_should_stop = Value('b', False)

# ===== YARDIMCI FONKSİYONLAR =====
def generate_password():
    password = "".join(
        random.choices(string.ascii_letters + string.digits, k=random.randint(4, 5))
    )
    return hashlib.md5(password.encode()).hexdigest(), password

def calculate_combinations(length):
    characters = string.ascii_letters + string.digits
    return len(characters) ** length

def get_chunk_range(total_combinations, chunk_id, num_chunks):
    chunk_size = total_combinations // num_chunks
    start = chunk_id * chunk_size
    end = start + chunk_size if chunk_id < num_chunks - 1 else total_combinations
    return start, end

# ===== NORMAL BRUTE FORCE ÇÖZÜMÜ =====
def brute_force_md5(target_hash, max_length=5):
    global is_cracking
    is_cracking = True
    characters = string.ascii_letters + string.digits
    total_attempts = 0
    start_time = time.time()
    
    for length in range(1, max_length + 1):
        progress_queue.put({
            'message': f"\n{length} karakterli şifreler deneniyor...",
            'type': 'info'
        })
        combinations_for_length = 0
        
        for combination in itertools.product(characters, repeat=length):
            if not is_cracking:
                return None
                
            total_attempts += 1
            combinations_for_length += 1
            candidate = ''.join(combination)
            candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
            
            if combinations_for_length % (100 if length <= 2 else 10000) == 0:
                progress_queue.put({
                    'message': f"Deneme sayısı: {total_attempts:,} - Son denenen: {candidate}",
                    'type': 'progress'
                })
            
            if candidate_hash == target_hash:
                end_time = time.time()
                progress_queue.put({
                    'message': f"Şifre bulundu: {candidate}",
                    'type': 'success',
                    'password': candidate,
                    'attempts': total_attempts,
                    'time': end_time - start_time
                })
                is_cracking = False
                return candidate
        
        progress_queue.put({
            'message': f"{length} karakter için toplam {combinations_for_length:,} kombinasyon denendi",
            'type': 'info'
        })
    
    is_cracking = False
    return None

# ===== MULTI-PROCESS ÇÖZÜMÜ =====
def generate_passwords_in_range(start, end, length):
    characters = string.ascii_letters + string.digits
    total = len(characters)
    
    passwords = []
    for i in range(start, end):
        password = ""
        n = i
        for _ in range(length):
            password = characters[n % total] + password
            n //= total
        passwords.append(password)
        if len(passwords) >= 10000:
            yield passwords
            passwords = []
    if passwords:
        yield passwords

def process_chunk_new(process_id, target_hash, length, start, end, progress_queue, should_stop):
    total_for_this_chunk = end - start
    tried = 0
    last_password = ""
    
    for password_batch in generate_passwords_in_range(start, end, length):
        if should_stop.value:
            return
        
        hash_batch = [hashlib.md5(p.encode()).hexdigest() for p in password_batch]
        last_password = password_batch[-1]
        
        for i, h in enumerate(hash_batch):
            if h == target_hash:
                found_password = password_batch[i]
                progress_queue.put({
                    'message': f"Process {process_id}: Son denenen: {found_password}",
                    'type': 'progress',
                    'processId': process_id,
                    'currentPassword': found_password
                })
                progress_queue.put({
                    'message': f"🎯 Process {process_id} şifreyi buldu: {found_password}!",
                    'type': 'success',
                    'processId': process_id,
                    'password': found_password
                })
                should_stop.value = True
                return
        
        tried += len(password_batch)
        
        if tried % 10000 == 0:
            progress = (tried * 100) // total_for_this_chunk
            progress_queue.put({
                'message': f"Process {process_id}: %{progress} - Son denenen: {last_password}",
                'type': 'progress',
                'processId': process_id,
                'progress': progress,
                'currentPassword': last_password,
                'tried': tried,
                'total': total_for_this_chunk
            })

def multi_brute_force_new(target_hash, max_length):
    global multi_should_stop
    multi_should_stop.value = False
    num_processes = min(cpu_count() * 2, 8)
    
    for length in range(1, max_length + 1):
        if multi_should_stop.value:
            break
            
        start_time = time.time()
        total_combinations = calculate_combinations(length)
        
        multi_progress_queue.put({
            'message': f"\n{length} karakterli {total_combinations:,} kombinasyon {num_processes} process'e bölünüyor",
            'type': 'info',
            'totalCombinations': total_combinations,
            'numProcesses': num_processes,
            'passwordLength': length
        })
        
        processes = []
        for i in range(num_processes):
            start, end = get_chunk_range(total_combinations, i, num_processes)
            combinations_for_process = end - start
            
            multi_progress_queue.put({
                'message': f"Process {i}: {combinations_for_process:,} kombinasyon test edilecek",
                'type': 'info',
                'processId': i,
                'combinationsForProcess': combinations_for_process,
                'startIndex': start,
                'endIndex': end
            })
            
            p = Process(
                target=process_chunk_new,
                args=(i, target_hash, length, start, end, multi_progress_queue, multi_should_stop)
            )
            processes.append(p)
            p.start()
        
        for p in processes:
            p.join()
            
        # Süreyi hesapla
        end_time = time.time()
        duration = end_time - start_time
        
        if multi_should_stop.value:  # Şifre bulunduysa
            multi_progress_queue.put({
                'message': f"✨ {length} karakterli kombinasyonların denenmesi {duration:.2f} saniye sürdü (Şifre bulundu!)",
                'type': 'info',
                'duration': duration,
                'passwordLength': length
            })
            break
        else:  # Normal bitti (şifre bulunamadı)
            multi_progress_queue.put({
                'message': f"✨ {length} karakterli kombinasyonların denenmesi {duration:.2f} saniye sürdü",
                'type': 'info',
                'duration': duration,
                'passwordLength': length
            })



# ===== FLASK ROUTE'LARI (ENDPOINTS) =====
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/get_password", methods=["GET"])
def get_password():
    global current_password
    hashed_password, real_password = generate_password()
    current_password = {
        "hash": hashed_password,
        "real": real_password
    }
    return jsonify({
        "password": hashed_password,
        "real_password": real_password
    })

# Normal Brute Force Endpoints
@app.route("/start_crack", methods=["POST"])
def start_crack():
    global is_cracking
    if is_cracking:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    while not progress_queue.empty():
        progress_queue.get()
    
    Thread(target=brute_force_md5, args=(current_password["hash"],)).start()
    return jsonify({"status": "success"})

@app.route("/stop_crack", methods=["POST"])
def stop_crack():
    global is_cracking
    is_cracking = False
    return jsonify({"status": "success"})

@app.route("/get_progress")
def get_progress():
    messages = []
    while not progress_queue.empty():
        messages.append(progress_queue.get())
    return jsonify(messages)

# Multi-Process Endpoints
@app.route("/start_multi_crack", methods=["POST"])
def start_multi_crack():
    global multi_should_stop, current_password
    
    if multi_should_stop.value:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    while not multi_progress_queue.empty():
        multi_progress_queue.get()
    
    multi_should_stop.value = False
    Thread(target=multi_brute_force_new, args=(current_password["hash"], 5)).start()
    
    return jsonify({
        "status": "success",
        "message": "Şifre kırma işlemi başlatıldı (1-5 karakter)"
    })

@app.route("/stop_multi_crack", methods=["POST"])
def stop_multi_crack():
    global multi_should_stop
    multi_should_stop.value = True
    return jsonify({"status": "success"})

@app.route("/get_multi_progress")
def get_multi_progress():
    messages = []
    while not multi_progress_queue.empty():
        messages.append(multi_progress_queue.get())
    return jsonify(messages)

if __name__ == "__main__":
    app.run()