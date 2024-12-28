import requests
import string
import hashlib
import itertools
import time
from multiprocessing import Process, Queue, Value, cpu_count
import ctypes

def get_target_hash():
    response = requests.get('http://localhost:5000/get_password')
    return response.json()['password']

def verify_password(password_guess):
    response = requests.post('http://localhost:5000/check_password', 
                           json={'password': password_guess})
    return response.json()['message'] == 'Success'

def try_password_range(chars, length, start_idx, step, target_hash, result_queue, should_stop, progress_queue):
    total_combinations = (len(chars) ** length) // step
    tried_count = 0
    
    for guess in itertools.product(chars, repeat=length):
        if should_stop.value:
            return

        if sum(chars.index(c) for c in guess) % step == start_idx:
            tried_count += 1
            password = ''.join(guess)
            
            # Her %1'lik ilerlemeyi raporla
            if tried_count % (total_combinations // 100) == 0:
                progress = (tried_count * 100) // total_combinations
                progress_queue.put((start_idx, progress, password))
            
            if hashlib.md5(password.encode()).hexdigest() == target_hash:
                if verify_password(password):
                    result_queue.put(password)
                    should_stop.value = True
                    return

def progress_monitor(progress_queue, num_processes):
    process_progress = {}
    while True:
        try:
            process_id, progress, last_guess = progress_queue.get(timeout=1)
            process_progress[process_id] = (progress, last_guess)
            
            # Toplam ilerlemeyi hesapla
            total_progress = sum(prog for prog, _ in process_progress.values()) // num_processes
            
            print(f"\rToplam İlerleme: %{total_progress} - Son denenen: {last_guess}", end="")
        except:
            break

def crack_password():
    print("Multi-process MD5 çözücü başlatılıyor...")
    target_hash = get_target_hash()
    print(f"Hedef hash: {target_hash}")

    start_time = time.time()
    chars = string.ascii_letters + string.digits
    num_processes = cpu_count()
    
    result_queue = Queue()
    progress_queue = Queue()
    should_stop = Value(ctypes.c_bool, False)

    for length in range(8, 17):
        if should_stop.value:
            break

        print(f"\n{length} karakter uzunluğundaki şifreler deneniyor...")
        processes = []
        
        # İlerleme monitörü process'ini başlat
        monitor = Process(target=progress_monitor, args=(progress_queue, num_processes))
        monitor.start()
        
        for i in range(num_processes):
            process = Process(target=try_password_range,
                            args=(chars, length, i, num_processes, target_hash, 
                                 result_queue, should_stop, progress_queue))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()
            
        monitor.terminate()
        monitor.join()

        if not result_queue.empty():
            password = result_queue.get()
            end_time = time.time()
            print(f"\n🎉 Şifre bulundu: {password}")
            print(f"Geçen süre: {end_time - start_time:.2f} saniye")
            return

    print("\n❌ Şifre bulunamadı!")

if __name__ == "__main__":
    print("Multi-process MD5 Çözücü")
    print("----------------------")
    crack_password() 