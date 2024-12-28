from flask import Flask, request, jsonify, render_template
import hashlib
import random
import string
import json
from threading import Thread
import queue
import time
import itertools
from multiprocessing import Process, Queue, cpu_count
import ctypes

app = Flask(__name__)

# Global değişkenler
progress_queue = queue.Queue()
current_password = None
is_cracking = False
multi_progress_queue = Queue()
multi_should_stop = None

def generate_password():
    password = "".join(
        random.choices(string.ascii_letters + string.digits, k=random.randint(4, 5))
    )
    return hashlib.md5(password.encode()).hexdigest(), password

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
            if not is_cracking:  # Durdurma kontrolü
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

def get_combinations_range(length, num_processes, process_id):
    """Her process için kombinasyon aralığını hesapla"""
    characters = string.ascii_letters + string.digits
    total_combinations = len(characters) ** length
    chunk_size = total_combinations // num_processes
    start = process_id * chunk_size
    end = start + chunk_size if process_id < num_processes - 1 else total_combinations
    
    return start, end, total_combinations

def process_chunk(process_id, target_hash, length, progress_queue, should_stop):
    """Her process kendi kombinasyon aralığını dener"""
    characters = string.ascii_letters + string.digits
    num_processes = cpu_count()
    start_idx, end_idx, total = get_combinations_range(length, num_processes, process_id)
    
    # Toplam deneme sayısı ve bu process'in yapacağı deneme sayısı
    chunk_size = end_idx - start_idx
    tried = 0
    
    combinations = itertools.product(characters, repeat=length)
    # İlgili process'in başlangıç indeksine kadar ilerle
    for _ in range(start_idx):
        next(combinations)
    
    for idx, combination in enumerate(combinations, start_idx):
        if should_stop.value or idx >= end_idx:
            break
            
        tried += 1
        password = ''.join(combination)
        
        # Her 10000 denemede bir ilerlemeyi raporla
        if tried % 10000 == 0:
            progress = (tried * 100) // chunk_size  # İlerleme yüzdesi düzeltildi
            progress_queue.put({
                'message': f"Process {process_id}: %{progress} - Denenen: {password} ({tried:,}/{chunk_size:,})",
                'type': 'progress'
            })
        
        if hashlib.md5(password.encode()).hexdigest() == target_hash:
            # Başarılı process'i vurgula
            progress_queue.put({
                'message': f"🎯 Process {process_id} şifreyi buldu!",
                'type': 'success',
                'processId': process_id,  # Hangi process buldu bilgisi
                'password': password
            })
            # Son durumu göster
            progress_queue.put({
                'message': f"✨ Bulunan şifre: {password}",
                'type': 'success',
                'highlight': True  # Vurgulama için flag
            })
            should_stop.value = True
            return

def multi_brute_force(target_hash, max_length=5):
    global multi_should_stop
    multi_should_stop = ctypes.c_bool(False)
    num_processes = cpu_count()
    
    for length in range(1, max_length + 1):
        if multi_should_stop.value:
            break
            
        multi_progress_queue.put({
            'message': f"\n{length} karakterli şifreler deneniyor...",
            'type': 'info'
        })
        
        # Her process için toplam kombinasyon sayısını göster
        _, _, total = get_combinations_range(length, num_processes, 0)
        multi_progress_queue.put({
            'message': f"Toplam {total:,} kombinasyon {num_processes} process'e bölünüyor",
            'type': 'info'
        })
        
        processes = []
        # Her process kendi aralığını alır
        for i in range(num_processes):
            p = Process(target=process_chunk, 
                       args=(i, target_hash, length, multi_progress_queue, multi_should_stop))
            processes.append(p)
            p.start()
        
        # Process'leri bekle
        for p in processes:
            p.join()
            
        if multi_should_stop.value:
            break

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
    
    # password.json dosyasını güncelle
    with open("password.json", "w") as f:
        json.dump({
            "password": hashed_password,
            "real_password": real_password
        }, f)
    
    return jsonify({
        "password": hashed_password,
        "real_password": real_password
    })

@app.route("/start_crack", methods=["POST"])
def start_crack():
    global is_cracking
    if is_cracking:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    

    while not progress_queue.empty():
        progress_queue.get()
    
    # Yeni thread başlat
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

@app.route("/start_multi_crack", methods=["POST"])
def start_multi_crack():
    global multi_should_stop
    
    if multi_should_stop and multi_should_stop.value:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    # Kuyruğu temizle
    while not multi_progress_queue.empty():
        multi_progress_queue.get()
    
    # Yeni thread başlat (multiprocess işlemi thread içinde çalıştır)
    Thread(target=multi_brute_force, args=(current_password["hash"],)).start()
    return jsonify({"status": "success"})

@app.route("/stop_multi_crack", methods=["POST"])
def stop_multi_crack():
    global multi_should_stop
    if multi_should_stop:
        multi_should_stop.value = True
    return jsonify({"status": "success"})

@app.route("/get_multi_progress")
def get_multi_progress():
    messages = []
    while not multi_progress_queue.empty():
        messages.append(multi_progress_queue.get())
    return jsonify(messages)

if __name__ == "__main__":
    app.run(debug=True)