#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--

'''
该脚本用于爆破采用了OpenSSL风格的KDF的RC4密文，也就是俗称的加salt密文
也可用于该模式的RC4加解密
当前采用调用原生CryptoJS库文件的形式，性能较弱，未进行优化和仿写

Todo:  支持内置密码规则
'''


import execjs

# Load CryptoJS library from JavaScript file
with open('./CryptoJS.js', 'r') as f:
    cryptojs_code = f.read()

# Initialize PyExecJS context
exec_js = execjs.compile(cryptojs_code)

# Define encryption function
def encrypt(plaintext, key):
    encrypted_text = exec_js.call('CryptoJS.RC4.encrypt', plaintext, key)
    return encrypted_text

# Define decryption function
def decrypt(ciphertext, key):
    decrypted_text = exec_js.call('CryptoJS.RC4.decrypt', ciphertext, key)
    msg = exec_js.call("CryptoJS.enc.Latin1.stringify",decrypted_text)
    return msg

# 预留文件读取
def read_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()


def read_key_from_file(key_path):
    with open(key_path, 'r') as key_file:
        keys = key_file.read().splitlines()
    return keys
    
# Example usage
def example():
    plaintext = "This is a secret message"
    key = "20416"

    encrypted_text = encrypt(plaintext, key)
    print("Encrypted text:", encrypted_text)

    decrypted_text = decrypt(encrypted_text, key)
    print("Decrypted text:", decrypted_text)

# msg_h = exec_js.call("CryptoJS.enc.Hex.stringify",decrypted_text2)
#  ["Hex", "Latin1", "Utf8", "Utf16BE", "Utf16", "Utf16LE", "Base64", "Base64url"];
# msg = exec_js.call("CryptoJS.enc.Latin1.stringify",decrypted_text2)
# print(msg)


    
if __name__ == "__main__":
    # ciphertext_path = "cip.txt"  # 替换为实际的文件路径
    # ciper = read_from_file(ciphertext_path)
    ciper = 'U2FsdGVkX196pWxlPoR49+G/eJXJcKqLOruhqNiHzQ==' 
    key_path = "pass.txt"  # 替换为实际的密钥文件路径
    keys = read_key_from_file(key_path)
    for key in keys:
        try:
            decrypted_text = decrypt(ciper, key)
            print(f"尝试使用 {key} 进行解密")
            print(decrypted_text)
            #  注意根据可能的解密后的字符，修改该字符串
            if "flag" in decrypted_text:
                decryption_success = True
                print("解密成功.")
                break  # 解密成功并包含"success"，停止尝试其他密钥
        except Exception as e:
            print(f"解密失败 {key} failed: {str(e)}")
 
    if not decryption_success:
        print("所有key已尝试，解密失败.")
    
    
    