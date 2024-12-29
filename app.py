from flask import Flask, request, jsonify, render_template
import hashlib
import random
import string
from threading import Thread
import queue
import time
import itertools
import os
from multiprocessing import Value
import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Thread, Lock

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

# Şifre uzunluk ayarları
MIN_PASSWORD_LENGTH = 1  # Minimum şifre uzunluğu
MAX_PASSWORD_LENGTH = 6  # Maximum şifre uzunluğu

def generate_password():
    """Rastgele şifre oluştur"""
    # Her çağrıldığında yeni bir uzunluk belirle
    password_length = random.randint(4, 6)
    
    password = "".join(
        random.choices(string.ascii_letters + string.digits, k=password_length)
    )
    return hashlib.md5(password.encode()).hexdigest(), password, password_length

# ===== ASYNC ÇÖZÜMÜ =====
async_progress_queue = queue.Queue()
is_async_cracking = False

# ===== THREAD ÇÖZÜMÜ =====
thread_progress_queue = queue.Queue()
is_thread_cracking = False
thread_lock = Lock()
active_threads = []

async def check_hash_batch(password_batch, target_hash):
    """Şifre batch'ini asenkron olarak kontrol et"""
    for password in password_batch:
        if hashlib.md5(password.encode()).hexdigest() == target_hash:
            return password
    return None

async def async_worker(chunk_id, characters, length, start, end, target_hash):
    """Her worker kendi aralığındaki şifreleri asenkron olarak dener"""
    tried = 0
    batch_size = 10000
    password_batch = []
    total = end - start
    
    for i in range(start, end):
        if not is_async_cracking:
            return None
            
        # Şifre oluştur
        password = ""
        n = i
        for _ in range(length):
            password = characters[n % len(characters)] + password
            n //= len(characters)
            
        password_batch.append(password)
        tried += 1
        
        # Batch dolduğunda veya son elemana gelindiğinde kontrol et
        if len(password_batch) >= batch_size or i == end - 1:
            result = await check_hash_batch(password_batch, target_hash)
            if result:
                # Şifre bulunduğunda son ilerleme durumunu gönder
                async_progress_queue.put({
                    'message': f"Worker {chunk_id}: %100 - Şifre bulundu: {result}",
                    'type': 'progress',
                    'workerId': chunk_id,
                    'progress': 100
                })
                return result
                
            # İlerleme raporu
            progress = min((tried * 100) // total, 100)  # 100'ü geçmemesini sağla
            async_progress_queue.put({
                'message': f"Worker {chunk_id}: %{progress} - Son denenen: {password}",
                'type': 'progress',
                'workerId': chunk_id,
                'progress': progress
            })
            password_batch = []
            
            # Küçük bir bekleme ekleyerek CPU kullanımını dengele
            await asyncio.sleep(0.001)
    
    return None

async def async_brute_force(target_hash):
    """Ana asenkron kırıcı fonksiyonu"""
    global is_async_cracking
    is_async_cracking = True
    characters = string.ascii_letters + string.digits
    
    for length in range(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH + 1):
        if not is_async_cracking:
            break
            
        start_time = time.time()
        total_combinations = len(characters) ** length
        num_workers = 12
        
        async_progress_queue.put({
            'message': f"\n{length} karakterli {total_combinations:,} kombinasyon {num_workers} worker'a bölünüyor",
            'type': 'info'
        })
        
        # Worker'ları hazırla
        chunk_size = total_combinations // num_workers
        tasks = []
        
        for i in range(num_workers):
            start = i * chunk_size
            end = start + chunk_size if i < num_workers - 1 else total_combinations
            
            async_progress_queue.put({
                'message': f"Worker {i}: {end-start:,} kombinasyon test edilecek",
                'type': 'info',
                'workerId': i
            })
            
            task = asyncio.create_task(
                async_worker(i, characters, length, start, end, target_hash)
            )
            tasks.append(task)
        
        # Tüm worker'ları başlat ve ilk sonucu bekle
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        
        # İlk tamamlanan task'i kontrol et
        for task in done:
            result = task.result()
            if result:  # Şifre bulundu
                # Diğer çalışan task'leri iptal et
                for t in pending:
                    t.cancel()
                
                duration = time.time() - start_time
                async_progress_queue.put({
                    'message': f"🎯 Async çözüm şifreyi {duration:.2f} saniyede buldu: {result}!",
                    'type': 'success',
                    'password': result,
                    'duration': duration
                })
                is_async_cracking = False
                return
        
        # Kalan task'leri temizle
        for task in pending:
            task.cancel()
        
        duration = time.time() - start_time
        async_progress_queue.put({
            'message': f"✨ {length} karakterli kombinasyonlar denendi ({duration:.2f} saniye)",
            'type': 'info',
            'duration': duration
        })

# ===== YARDIMCI FONKSİYONLAR =====
def calculate_combinations(length):
    characters = string.ascii_letters + string.digits
    return len(characters) ** length

def get_chunk_range(total_combinations, chunk_id, num_chunks):
    chunk_size = total_combinations // num_chunks
    start = chunk_id * chunk_size
    end = start + chunk_size if chunk_id < num_chunks - 1 else total_combinations
    return start, end

# ===== NORMAL BRUTE FORCE ÇÖZÜMÜ =====
def brute_force_md5(target_hash):
    global is_cracking
    is_cracking = True
    characters = string.ascii_letters + string.digits
    total_attempts = 0
    start_time = time.time()
    
    for length in range(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH + 1):
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
    start_time = time.time()  # Başlangıç zamanını kaydet
    
    for password_batch in generate_passwords_in_range(start, end, length):
        if should_stop.value:
            return
        
        hash_batch = [hashlib.md5(p.encode()).hexdigest() for p in password_batch]
        last_password = password_batch[-1]
        
        for i, h in enumerate(hash_batch):
            
            if h == target_hash:
                found_password = password_batch[i]
                end_time = time.time()  # Bitiş zamanını kaydet
                duration = end_time - start_time  # Süreyi hesapla
                
                progress_queue.put({
                    'message': f"Process {process_id}: Son denenen: {found_password}",
                    'type': 'progress',
                    'processId': process_id,
                    'currentPassword': found_password
                })
                progress_queue.put({
                    'message': f"🎯 Process {process_id} şifreyi {duration:.2f} saniyede buldu: {found_password}!",
                    'type': 'success',
                    'processId': process_id,
                    'password': found_password,
                    'duration': duration
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

def multi_brute_force_new(target_hash):
    global multi_should_stop
    multi_should_stop.value = False
    
    # Sabit 12 process kullan
    num_processes = 12
    
    multi_progress_queue.put({
        'message': f"{num_processes} process ile çözüm başlatılıyor",
        'type': 'info'
    })
    
    for length in range(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH + 1):
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

# ===== THREAD ÇÖZÜMÜ =====
def thread_worker(thread_id, characters, length, start, end, target_hash):
    """Her thread kendi aralığındaki şifreleri dener"""
    global is_thread_cracking
    tried = 0
    batch_size = 10000
    total = end - start
    start_time = time.time()
    
    current_batch = []
    for i in range(start, end):
        if not is_thread_cracking:
            return None
            
        # Şifre oluştur
        password = ""
        n = i
        for _ in range(length):
            password = characters[n % len(characters)] + password
            n //= len(characters)
            
        current_batch.append(password)
        tried += 1
        
        # Batch kontrolü
        if len(current_batch) >= batch_size or i == end - 1:
            with thread_lock:  # Hash hesaplama sırasında kilitle
                for pwd in current_batch:
                    if hashlib.md5(pwd.encode()).hexdigest() == target_hash:
                        duration = time.time() - start_time
                        thread_progress_queue.put({
                            'message': f"🎯 Thread {thread_id} şifreyi {duration:.2f} saniyede buldu: {pwd}!",
                            'type': 'success',
                            'threadId': thread_id,
                            'password': pwd,
                            'duration': duration
                        })
                        is_thread_cracking = False
                        return pwd
            
            # İlerleme raporu
            progress = (tried * 100) // total
            thread_progress_queue.put({
                'message': f"Thread {thread_id}: %{progress} - Son denenen: {current_batch[-1]}",
                'type': 'progress',
                'threadId': thread_id,
                'progress': progress
            })
            current_batch = []
    
    return None

def thread_brute_force(target_hash):
    """Ana thread kırıcı fonksiyonu"""
    global is_thread_cracking, active_threads
    is_thread_cracking = True
    characters = string.ascii_letters + string.digits
    
    for length in range(MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH + 1):
        if not is_thread_cracking:
            break
            
        start_time = time.time()
        total_combinations = len(characters) ** length
        num_threads = 12  # Sabit thread sayısı
        
        thread_progress_queue.put({
            'message': f"\n{length} karakterli {total_combinations:,} kombinasyon {num_threads} thread'e bölünüyor",
            'type': 'info'
        })
        
        # Thread'leri hazırla
        chunk_size = total_combinations // num_threads
        threads = []
        active_threads.clear()
        
        for i in range(num_threads):
            start = i * chunk_size
            end = start + chunk_size if i < num_threads - 1 else total_combinations
            
            thread_progress_queue.put({
                'message': f"Thread {i}: {end-start:,} kombinasyon test edilecek",
                'type': 'info',
                'threadId': i
            })
            
            t = Thread(
                target=thread_worker,
                args=(i, characters, length, start, end, target_hash)
            )
            threads.append(t)
            active_threads.append(t)
            t.start()
        
        # Thread'leri bekle
        for t in threads:
            t.join()
            
        if not is_thread_cracking:  # Şifre bulunduysa
            break
            
        # Süreyi hesapla ve rapor et
        duration = time.time() - start_time
        thread_progress_queue.put({
            'message': f"✨ {length} karakterli kombinasyonların denenmesi {duration:.2f} saniye sürdü",
            'type': 'info',
            'duration': duration
        })

# Thread endpoints
@app.route("/start_thread_crack", methods=["POST"])
def start_thread_crack():
    global is_thread_cracking, current_password
    
    if is_thread_cracking:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    while not thread_progress_queue.empty():
        thread_progress_queue.get()
    
    Thread(target=thread_brute_force, args=(current_password["hash"],)).start()
    return jsonify({"status": "success"})

@app.route("/stop_thread_crack", methods=["POST"])
def stop_thread_crack():
    global is_thread_cracking
    is_thread_cracking = False
    return jsonify({"status": "success"})

@app.route("/get_thread_progress")
def get_thread_progress():
    messages = []
    while not thread_progress_queue.empty():
        messages.append(thread_progress_queue.get())
    return jsonify(messages)

# ===== FLASK ROUTE'LARI (ENDPOINTS) =====
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/get_password", methods=["GET"])
def get_password():
    global current_password
    hashed_password, real_password, length = generate_password()
    current_password = {
        "hash": hashed_password,
        "real": real_password,
        "length": length  # Dinamik uzunluğu kullan
    }
    return jsonify({
        "password": hashed_password,
        "real_password": real_password,
        "length": length,
        "min_length": MIN_PASSWORD_LENGTH,
        "max_length": MAX_PASSWORD_LENGTH
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
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    # Kuyruğu temizle
    while not multi_progress_queue.empty():
        multi_progress_queue.get()
    
    # should_stop değerini sıfırla
    multi_should_stop.value = False
    
    # Yeni thread başlat
    try:
        Thread(target=multi_brute_force_new, args=(current_password["hash"],)).start()
        return jsonify({
            "status": "success",
            "message": "Şifre kırma işlemi başlatıldı (1-5 karakter)"
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"İşlem başlatılamadı: {str(e)}"
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

# Async endpoints
@app.route("/start_async_crack", methods=["POST"])
def start_async_crack():
    global is_async_cracking, current_password
    
    if is_async_cracking:
        return jsonify({"status": "error", "message": "Zaten çalışıyor"})
    
    if not current_password:
        return jsonify({"status": "error", "message": "Önce şifre oluşturun"})
    
    while not async_progress_queue.empty():
        async_progress_queue.get()
    
    def run_async():
        asyncio.run(async_brute_force(current_password["hash"]))
    
    Thread(target=run_async).start()
    return jsonify({"status": "success"})

@app.route("/stop_async_crack", methods=["POST"])
def stop_async_crack():
    global is_async_cracking
    is_async_cracking = False
    return jsonify({"status": "success"})

@app.route("/get_async_progress")
def get_async_progress():
    messages = []
    while not async_progress_queue.empty():
        messages.append(async_progress_queue.get())
    return jsonify(messages)

if __name__ == "__main__":
    app.run()