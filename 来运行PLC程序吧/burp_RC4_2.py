#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--

'''
该脚本用于爆破采用了OpenSSL风格的KDF的RC4密文，也就是俗称的加salt密文
也可用于该模式的RC4加解密
当前采用调用原生CryptoJS库文件的形式，性能较弱，未进行优化和仿写
支持内置密码规则，已完成
TODO： 支持多线程
'''


import execjs  # pip install PyExecJS  # 需要注意， 包的名称：PyExecJS  
import argparse
import itertools
import string

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

def generate_num_combinations(length):
    # 使用 itertools.product 生成所有可能的数字组合
    num_combs = itertools.product(string.digits, repeat=length)
    # 将组合转换为字符串
    return num_combs
    
    
def generate_mix_combinations(length):
    # 使用 itertools.product 生成所有可能的数字和大小写字母组合
    mix_combs = itertools.product(string.digits+string.ascii_letters, repeat=length)
    # 将组合转换为字符串
    return mix_combs

def crack(ciper, keys):
    for key in keys:
        try:
            keyf = ''.join(key)
            decrypted_text = decrypt(ciper, keyf)
            print(f"尝试使用 {keyf} 进行解密")
            print(decrypted_text)
            #  注意根据可能的解密后的字符，修改该字符串
            if "flag" in decrypted_text:
                decryption_success = True
                print("解密成功.")
                break  # 解密成功并包含"success"，停止尝试其他密钥
        except Exception as e:
            print(f"解密失败 {keyf} failed: {str(e)}")
 
    if not decryption_success:
        print("所有key已尝试，解密失败.")


# msg_h = exec_js.call("CryptoJS.enc.Hex.stringify",decrypted_text2)
#  ["Hex", "Latin1", "Utf8", "Utf16BE", "Utf16", "Utf16LE", "Base64", "Base64url"];
# msg = exec_js.call("CryptoJS.enc.Latin1.stringify",decrypted_text2)
# print(msg)
    
    
def main():
    parser = argparse.ArgumentParser(description="用于破解加盐类型的RC4密文")
    parser.add_argument("-cipher", type=str, metavar="密文", help="输入要尝试解密的密文")
    parser.add_argument("-kf", type=str, metavar="密钥字典文件名", help="从指定字典文件获取key列表")
    parser.add_argument("-kln", type=int, help="生成指定长度的纯数字key列表，建议不要超过6位")
    parser.add_argument("-klm", type=int, help="生成指定长度的key列表(数字加大小写字母混合），建议不要超过4位")
    
    args = parser.parse_args()
    cipher = args.cipher
    
    if not any([hasattr(args, 'kf'), hasattr(args, 'kln'), hasattr(args, 'klm')]):
        parser.error("必须提供至少一个参数: --key-file, --key-list-name, --key-list-method")
    if args.kf:
        keys = read_key_from_file(args.kf)
        crack(cipher, keys)
    if args.kln is not None:
        print(f"生成指定长度{args.kln}的纯数字的key列表：")
        keys = generate_num_combinations(args.kln)
        crack(cipher, keys)
    if args.klm is not None:
        print(f"生成指定长度{args.kln}的key列表(数字加大小写字母混合）：")
        keys = generate_mix_combinations(args.klm)
        crack(cipher, keys)
    
if __name__ == "__main__":
    main()
    # ciphertext_path = "cip.txt"  # 替换为实际的文件路径
    # ciper = read_from_file(ciphertext_path)
    # ciper = 'U2FsdGVkX196pWxlPoR49+G/eJXJcKqLOruhqNiHzQ==' 
    # key_path = "pass.txt"  # 替换为实际的密钥文件路径
    