import asyncio
import string
import hashlib
import aiohttp
import itertools
import time
from concurrent.futures import ProcessPoolExecutor

def calculate_hash_sync(password):
    """Senkron hash hesaplama - CPU işlemi"""
    return hashlib.md5(password.encode()).hexdigest()

def generate_passwords(length, start_idx, step):
    """Belirli bir uzunluk için şifre kombinasyonları üret"""
    chars = string.ascii_letters + string.digits
    passwords = []
    for idx, guess in enumerate(itertools.product(chars, repeat=length)):
        if idx % step == start_idx:
            passwords.append(''.join(guess))
            if len(passwords) >= 10000:  # Her 10000 şifreyi toplu işle
                yield passwords
                passwords = []
    if passwords:
        yield passwords

async def verify_passwords_batch(session, passwords, target_hash):
    """Şifreleri toplu olarak kontrol et"""
    # Önce hash'leri CPU'da hesapla
    loop = asyncio.get_event_loop()
    with ProcessPoolExecutor() as pool:
        hash_futures = [loop.run_in_executor(pool, calculate_hash_sync, pwd) for pwd in passwords]
        hashes = await asyncio.gather(*hash_futures)
    
    # Eşleşen hash varsa şifreyi doğrula
    for password, current_hash in zip(passwords, hashes):
        if current_hash == target_hash:
            async with session.post('http://localhost:5000/check_password', 
                                  json={'password': password}) as response:
                data = await response.json()
                if data['message'] == 'Success':
                    return password
    return None

async def try_passwords(session, start_idx, step, length, target_hash):
    total_combinations = (len(string.ascii_letters + string.digits) ** length) // step
    tried = 0
    
    print(f"Worker {start_idx}: {length} karakter uzunluğunda şifreleri deniyor...")
    
    for password_batch in generate_passwords(length, start_idx, step):
        tried += len(password_batch)
        if tried % 50000 == 0:
            print(f"Worker {start_idx}: {tried:,}/{total_combinations:,} denendi")
        
        result = await verify_passwords_batch(session, password_batch, target_hash)
        if result:
            return result
    
    return None

async def get_target_hash():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://localhost:5000/get_password') as response:
            data = await response.json()
            return data['password']

async def crack_password():
    print("Geliştirilmiş Asenkron MD5 çözücü başlatılıyor...")
    target_hash = await get_target_hash()
    print(f"Hedef hash: {target_hash}")
    
    start_time = time.time()
    num_workers = 16  # Worker sayısını artırdık
    
    connector = aiohttp.TCPConnector(limit=100)  # Eşzamanlı bağlantı limitini artır
    async with aiohttp.ClientSession(connector=connector) as session:
        for length in range(8, 17):
            print(f"\n{length} karakterli şifreler deneniyor...")
            
            tasks = [
                try_passwords(session, i, num_workers, length, target_hash)
                for i in range(num_workers)
            ]
            
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result:
                    end_time = time.time()
                    print(f"\n🎉 Şifre bulundu: {result}")
                    print(f"Geçen süre: {end_time - start_time:.2f} saniye")
                    return result
    
    print("\n❌ Şifre bulunamadı!")
    return None

if __name__ == "__main__":
    print("Geliştirilmiş Asenkron MD5 Çözücü")
    print("--------------------------------")
    asyncio.run(crack_password()) 