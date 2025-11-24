import base64
import sys

# Kiểm tra thư viện base92
try:
    import py3base92 as base92
except ImportError:
    print("[-] Lỗi: Chưa cài thư viện base92.")
    print("[-] Hãy chạy lệnh: pip install py3base92")
    sys.exit(1)

encoded_str = "MmtiTjY5MzFlaVh1UGtSZGpZV1VmRmp1MnRHV2hpOVhKdEFYa25yMW13M0I4SFhyV2pxcGt0NnpTb3ZOUnNxV1hmZndZRG9leW9GV216NXR3b0VyUlFlbmIxVEZTYkxoWWVtZmZoSkNzakpmZGlXYVBwU3VHbnBYbXJ1UENXclVycTVlR21xSDJZRFlpcjNoVGtWVGJzN3lMV0tXZ0hSUU1LUEU0WE5zaThBSzhpc0JmQ3RSWTVxVkVnOXBkTUFGTjdzc0R5M3ZldEF3bUwxVTNxdTlRWGp4N1hCMlVKdmU3RWpVWVVBUUM3dlpSdktKeThWTTZnMjJVNmV5V1o0R1hBcTE4WXhESzZ0VEVtMjJwanNhUlZuaDVGdnN4eDFqRHhObmkzOG1ZUFY1cGJMdHNocHdKWUhtOE1NVThhOXJWdWhXSzRZTjRtQ1JLOThHb2hxRVl0anFzQjU5QXN1RFZ0TVdVQWhQbVRUdDdrd3JLMVoyaWljZHBSc2NIOXZhNGhtQkM5QWNWemRkaTFSeFRtd3hUZVloTjRXNlpDOWpRN2ZrVDhiYlVEaDJoRmVMUEZlejhTOVFDcUxyOHdkZ2R1VFg5aFNTOG9LQXByUHJjd2ROR2c0V1BtRHhGekJqZ1V3d21KeHc3czFrQkhyNHlEVmhrS00yTlpiS1VkOHJaQjR6ZTNYZlZwanZ2cmEyZzd0dmNKYkg2ZEZvMVdZdzRIckMzVWNaemZGbUdwRE5TTkxLZk4xNXRaNFFjWW1HRG1iaFdHTVhMQm1GTGJwalFNWmRXNHFoOFpiTTk4R044aHI2c01Ndmd6VEdlTEZwQUVWaGVqQWlkR2MycHljb2FtRzVvYURQbmJweTF6empqdlBlV2Q0czNtTlZhWGUxaWpBVnUzU0NUNUdBRFozVGdDTDJiQk5QVExlWlZLQ1ZVOHJRck1xcmd0Y1BtWlljdWFBS3B4cGMxVFltZGlnYW43RnB2c2czck1hN3YzUnN6R1RRbWliSnhXdGs0N1d6bm1aTFZjRUR5WGQzZnlUdXRmeDJRVGRxV2YyTjJVTWFUYXNoTFRvNkN4eWVjQkJRZmpDdmY4UGlaODlzaHR6aFQ1NUJDZ0pmdHVnZ2ZqZG5uZFFwQVhLVnk4NW8yaHFpa05iYUZnV2c1QXZjTHZRMXpYelN6bUFtQWgyQzFNWTFHUllSVFl1YUd4VlRFajVVb0NVVnhDenhrRTV3cUhoWUZ6bU5SSkpub1l6ZmNCWVpabzJ4ZW91SjIxMkpEdmdnTVMzZ1NtU0pRNlp0Q3ptUmt4U3ZKNXg4aW1IMWVZZ0M4NEVzZzltN1l4ZEZhV0tudWZ1QVZrb3dIZzZWbkxNV2pQVExwRk1TazF6MmFra2c5Z01TOUFqVGY1Rk5kZmdOUDJxZ1pMZlVVZTI1M1Y1WlVQcWdubkQ5bzJXOVB5bnZjelROWVkxSlhNSktiUmRyRmp5SGZtZEppak5rVWpGNzlhczZEUGhuVFNWM0QxS0Q2UkxaODl0bWZadmFTODNrNE5oQzZEdHlrQ2tBdDFtRlRjQkVWRVlKbTNzYnVnZnVYMjN6akJycFN6dEVMMVhESkFhd2RWUE5wTjdGRVJ4UG9iM2tycXpHZHpoZTJ1MlpVNmFlQWFISmhhS2I3cjV6QXJUQXA4eEgxVWdlOXV6bVRWNWtlaHJLNEdMYmNncGJYN1l6eXFDSGlMWUwxTDJoMU5aUnA4MXc2Y3RMMzdCd0poQ0xwUU5wWDJFdFc4cG9iczU0bjNYaWlncUY5NXNDZGoyNVBOOGNyQjk3YmRXaXg0WWE2UUJnMVIyVnFUb0xwWUhmUGpTNGtrOGdUZHpYczJReHExODVDZTkzZnNrRlh6aUNERW9IVDJBb041V1dVN3V5c3NzTnpmaFhlVTZ2aDI1bk5NOFV0dnByUUpqMTF0RUpMUjRHdVdwRno1MnlFNEdIU1VOTWR0NlNKYnJhWGFFYnZuU1RqUjJTTTFxYjlBazdCaHlMSkpVc3JpeDVSdTlXUkt4dlk2TkxMNlZMTjlkam9kdG95aDZUaUJqaXFrM2paUVJrQTF0S2NZd1FnRlVRZlo3YnY2OVRpZ2l1YjdMUUtxY0VHYUNxa0tDNjZISFRCbzJFYUNocjlxS2huaTNMRTE1WlBQYUJ3NExGYjVVVTdBNGcyd3lCaUFVOUFOZFBkaUhWS0JLVmoxTGJ0TVhTUnNTRmJaR3E4TUVmNzZ3emZ3UW82M2pMeDhyMUNZUm00b2c5WUtOM2kzTUVTWHlxTTNNcXZLVjNCWDhoWHBmejU0QllZdzJCa2k0WUtiZ0xxaVdSWms0ZHRVN1ZiZ0NuTHVnWDNjbThuZGhQUzlScjlkaGJrV3JCTlpVUWJFS2o2dnpvRkMzbXQ0UmJ5VjN6bUhmalpXc2lGcWllUUExanVKZnpjMkNpakZHODFialJzVmtqNlpyZlpkeVZZb2lGbWI2cUZQWG40ZVVNSlNibjJWSkt0SHkyRGJ4OFc3c0d4WnN4TVJrcGcyQng4UDltTk5pSnAyMm5tN0RUTFcxaURRdnJ3OWtjTEtlcVN5blNpOHhTZDhpTndWR0E3V0h6RWV1alVxaFRETXpBOFIxQU1TN3dmNGVaZ2R1UVhxUVVvcDkxYUtaeDhmc1RqQUVjakVraWF2QlBvSkVwS0hlVHJ1emFvYkRLZmhtZUpjb0pnQ2pDS0hjckRhSm90M3VzcnJxR3dNY2t6UGZEcDR2azl2MnM0S1RnZU0xWURGZUxuVWdRY3JoeGRpWXY3SFBSOUo1dkZlbVBCck1iYjZaTkJ3V1ZhbTdVWW96cU5la3FwZFNNNmtQTE5iOGVGeWNudnBWWU1nWmcxdXo5elplQ3lQZjZTMTZuSmdVZ200ZkhROEMxUlZ6RzR5bUM0dXhtMnV6RFZBWnhNTHBjbk1Ebm0yTGlDZ1VkNHdlQnBMRGVwdjVuUDh2UVhTVW9aeTNlZVB2RVdIQXBCZjN2WVZFcFBNbjlnNUtNUXRNOEFUWmNNNjJGZ0NtblNYZ0JoWmRVQVRVVkp6dllIRGZ3bUpKSmpTenh0U0hyNmlhVjNqUlg3b21nQ2d3eFFtQndSNHBwalpkZVhwTEJVZGp1Zm1yUGY3QUpCMWlETnRRcjh6QzltbjliNGhLRDRucmFibkJnZVcxcWE1aktSWFM5dnFBcHRLUGZkWW1NQVVTMUJGOVd1eWtuVVVUU2JnajNkeEg0eDdCQjdUMnJES2NjemhHR0NxYVp2WHBaQzdKcVRFVjdacWgxSlNraUdvSlFNR1hIanJCVkhiQ1dwY1ZiWlh3a1V2TkhXQ2Jpb1M5WDJ4RWFLb2ZhTnZkemp0RWpYakNaRVNuNG5SaUZHNVRGazNyUUZ4YlB3OFJtY0ZBRnRwWU1vNUZ5YVVEQVhWazEydjFiV1pMYW1hM2FQcnBoRWZMdkN1YTVrU1g5NzdFTmF0eURycTJOM3F1Z1VCMm43YkNxQWN5N2NaMUJ1Y3lhcUc2d2NWYU54Y2E3UHo0eWtHbkhVWm5aakExa2RWZVpHOGI1ejVLZnBMcUdyWFlqdGhaVjg5UDVOMzlQZGZ5SlVveTFDWURvdzYxNWdGajZvaTFuQmNIcnVhdzU2WGdQYWhmNTVXSGQxNFdGR0J5MzZHc2pjYmlhVnpLTmJtRWhzcEdDZlVqYjJRY2pyTWR6WVdYeEw0THoxVVZwRFV1VWZBVDlUeXVuMnZXUmFwZTY5cjk5Zm1OMlA4UGJmTVl5aXJkZ0FBd1FwUTJLcExzN2dlUFFGOHdnYm1uM3JHc0hYVlVzN1JSbjhuS0xMVHRNMTRTQlFwdjdCV3ZYcWIxQmRHNkVmc2JBamIyZm9UOFRQNnlrNUNxMXk5MjFrN2NSWlVWOVZjc29qMjkxclozNDg1Ym1tZWhqaVpobWRiYVhnNVg0OHJEVGttOHJTazlKZ1BMRGF0QkhmQXc1cjlkU1RFSGRwbVFFbkZYaTRRNkJRS0U3U2ExUjRSZWVickpEOTd2anJtTVhVNGt0Skh2aXcxV0dxdXcxQ25pOTNmYjlSbzh1dXBiS0RMYmZ6Y2RESGJicHpIaXdmc1haR1dDTTNEZk5Bd0JQdGIxamRuUWFNRmpGMm05aWNLUUppZG9YRkp3clp2cHg1SHVaYUM4R0dndHpkSHRSNVMzM3VHUUZqVUhORGRnRUh3OTFSR2hLTDJIQmlheGRBU2tFWTR4end6UDhtckpjY01DVFd6Q2tiWG5aeTRHakEycDNRYTFyNnJwWXhNRGFUUkhEcmtiRXlVU3pveFhmV3NYSk4yM1FaUHpEdzY1WVVoMlVDUktyQVJMa2JCODh0aFRrTWgzWU5ld05zbkdjNVVuRTRMUFEyNXVuS1ZDem9nU0pxazJ3YjN3RGJSYmVydDJ3d29ENDRNWVJqcTVOVUJwc3BXSkpDY3U5d2tmdzVLMndBcmZaZktBamhIV2ltazhHREZVMjdEUkdHVFdCVThWd3VSVHd6YVVyMXBENDZ4NGpCTUZyZmVQekpHV0NxVDRUSEVLeTd4cXhNOVZwNXRxRUFyWmhqRVEySER1VVFld3VDSGFWN1loUjVCc3EyOFhEWWZ5cFNoUHVzUWVlUDNwck1DQWFqdVNvUXBTaGh0NkU4ZGFEWENmcVBqdTd1MVlCcTR6dE1yTUJwd05LZUZEUW1ucVhXZWlRNjlHSGhBN3p1WWk0Vmg2OVF6a3NlbXM5ZzI5OEtDQ1g1ZXRTR25Vdm1lcThoaGdqVTZRVnJ2Ykw0VEQ5UndLSFp1M0p2TVU0UkQ3OGdMVk1ybUtCOTVLTGd6Tm5YNjlEZ0FzNm96ejlrMTNwSFFzVjRCdTV4cDdZZ0Z1UW4xRzFLSFhDazJpVnIxRzgzVGVlak1Sb0hZRG9paEhGQ2V3OWlGd2NwQWo4Ukp3RnpCVVV2N0VBcXRrOVhtRE5KTGJCejhhOU5RNld4Yml4Q200ckp2UEFEazFUZ01oaDVkVkxnWE5rRVZmcW5jd3c2WllkRm02VjR0b0dEaFI0dkp3QjlmNkFjeEJhcDhNSGpvYmNDM0oyWHg2RzRnOUN6emd6UEZEMTI1cnhETG5YMzlvRGJQV3FLekxlaWFpdEJUOHZGM0VZeDhhUGl0NGVhcmRhTmZwWHJxTjZYN1Z3VTZzVDlZQkxWUmp2TnRpQlViVEVaRnh3NVNMOVBVVERvQXZUc041NFRoVGJaNmUxR1BpTGlzbkV3cEd5S01tZzRmUG1WclpIRnF5UU1hOHF6cHR4d25jYlBha0dTa2JkNWRhUWl4YmoxUmQ5d3hoOVZ3d1loNnVVS21TQ05lakdXUWhSNHVjM0h6WktGNFB1cU5rQUtWYWYxQlhRSGZIM2tTekh5Zng1U0d1MWVvZEZMcHJVc3FFY1hBdEFWcXlvZFFnaVRla2JpcHJTQll6dzZWNnppZVc1WWF6eThEUW9jZ3FySFNhc3BlQ0xUeDhEU2NXaDRXRUZqTURkREFKV3h3ZHFMQm9DRTg2QjZ1bmtwd3ZSOGk2Nks4dW16TWdGOWk0NWF2am1NUFpjRHU2RkhaMm9nVEZHQjU5aVFMVVpzWkF2aUhxWjdueVU2aG1jMWdjYnRpOTJMMW1WMW5wYlpUZFRONERWYUoxckI5OUdEWmpHYzE2dmNDUDFBclprcDgzOHJVbnpwRllmRllzWkNEMnhhMWNBM0VrSkphRlJvUVNDZVdlNWlzOWNHa3UxSkhxY0dDRGhSTG5ybk5udkR5OGhaUzFuWjFzV0NaM2lkRUM4OTZSUTNEa3pZY3pWZjFlakxOSmtyd2Y0eWVwVjNWSjNnNlpBdWZBclM2NHBSVHpyMlh3VVdqZjVBQlRiNk05RTNMOGdHNHNIaVhkcGl5cGJHTTg3YXNMQ3NDRmtEU005cmcyeldQZXFMNXZZenpCdXc5YVE3dlVHVGJDUndLUXN6QnhtSldhZW05N1VYQWtRUjNWbzJwTlQzNld6Y2tmUG9LV0h4UmFNYzg2NWZSd3A1NmtFaGZ6Qmk4NjF2QUdpQ3A3bm5yOTY4QWhjZVFnUnF0ZkRvS0hmblNLUlhTY3VQZHI3OXE1RjE3TmdkOVU4NUMzQ0E1MTlCdnJ3TnRXbWRxYXhvRms4bjhvUXdZd2tXTlhMMTVuUUo5ekVIUFNpOW4zWlJCN0p5WXZzeHp5d0Z2YlZHRTJoWlcxQnNlVzhrY1o2c05mZUc1d1FQYXkyYm9UNk1jN2N1Y1hOTGZhNmtUS210NGZrOGJ4cENIa1U5SFJGREdReXV0eU5SMUw0b3lndUh5UkxMTnZVR2d2aG9GaEhDa2dhcm5rYWgzbVZpSFY4TkpLZ0s1aGMyNlpIS2Iya3RQRzE4dmtQb3puNEw5a05UZGNXcVozYmpIdmd4OTJTTHQxZ3M5elU2bnU3MXZUblVKQmZpd25pVTdBdlBwcUhVTjVaVGFGQzM4VEJ2aHBONmVUSzZoeGFNZGZ2YlRha0dQR2V3OHlYdXJaS0pvN05GZ3hjdjU0bUtDR2lBUWEyUjZTU1BFR2UzbW1WN2F4ZXAyY2p0ZGZOSlYzd0NNTjZOM1lhUlBGSFZaVXFuemZETm11em94RjhMY1lVWTNpYjFHb0RKRktKc0QzcTE2M1dWbnBpVXlHaTZ1cU5WTDNHRUs1VE10U0hGaXJKaGt2bkZHVjFiTDQxRFhGSDJveEVOalp5bU16Z1dLekpwNlkxYXI1ekxQanNCWm40Q0o0UUtUZ0pkQW1Ib1NxcEU4a3VkSFhVWGZrUDJWWENQelhhZHg1NzdKWXFHU0VXaE4zQkJWa3F3MW85eVJqMndia0pTY0F3TjFqVTZETmFQdE0yaFIycG9mcUp1YndvYlJGaEJpcDR5UGY3d2N4VEJ3V3BVbWFvZ1A2ZlY3NjdRU0ZCaW44aFl4NDl4eGFYN3RtRDRFQlZ0cERHTGZOYzd2V2NFVDNCV1dhUUduZmhXTlRmUHVmcGtIRDR1blA1YlNXVDFyZ2VNMUpvQTJkWDY0TUxSalNyR1pRVDdXRHdaNDZrMXhnVEdib1EzTkxrd3Y4NzJRcWlMOGJrcXJDWThCS3pLcmNGbkJEQVRFYnFFamRyZUR4cGFjQmZoRUNOSzQ0b2J3YlRNSzZXaHZEdE5HWTRiUVV5N3RoVGlnaUtES2lEbmZqTkVTNzVzS0FjbmZpdEtia2dVTGtTZVMxR25zMmpidG1CaDJBUFdYeXJ4M0NMZTRVRTlxdkxWTG9IMkFWcWliOG05UEV5OUI0Z0h0OUE0YnBnU3dCc0t0WXhxVldKMUQ0cjRHTEc1YUdYd1FMcjVkWXp3QTNrWVRaUVNieG4xdHh3c1RjWkI3M0FkdDc2YmVTR2pWUm1xN1FtUkpzQkU0M3JVdTFOQ1F2AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w=="

def b58decode_custom(s, alphabet):
    base = len(alphabet)
    num = 0
    try:
        for char in s:
            if char not in alphabet:
                # Nếu gặp ký tự lạ, coi như sai bảng mã
                return None
            num = num * base + alphabet.index(char)
    except:
        return None
    
    combined = []
    while num > 0:
        num, rem = divmod(num, 256)
        combined.append(rem)
    
    for char in s:
        if char == alphabet[0]:
            combined.append(0)
        else:
            break
            
    return bytes(combined[::-1])

# Các bảng mã Base58 phổ biến
ALPHABETS = {
    'bitcoin': '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    'ripple':  'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz',
    'flickr':  '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
}

# 1. Decode Base64
print("[*] Decoding Base64...")
data_stage1 = base64.b64decode(encoded_str)
payload_stage1 = data_stage1[:-256]
payload_str = payload_stage1.decode('utf-8', errors='ignore')

# 2. Thử các bảng mã Base58
print("[*] Decoding Base58 (Testing alphabets)...")
stage2_result = None
used_alphabet = None

for name, alpha in ALPHABETS.items():
    print(f"    - Trying {name} alphabet...", end=" ")
    res = b58decode_custom(payload_str, alpha)
    if res:
        # Kiểm tra sơ bộ xem kết quả có phải Base92 sạch không
        # Base92 alphabet (standard)
        b92_chars = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}`~"
        res_str = res.decode('latin1')
        
        # Lọc bỏ null bytes ở cuối nếu có (đôi khi là padding)
        res_str_clean = res_str.strip('\x00')
        
        # Kiểm tra tỷ lệ ký tự hợp lệ
        valid_chars = sum(1 for c in res_str_clean if c in b92_chars)
        ratio = valid_chars / len(res_str_clean) if len(res_str_clean) > 0 else 0
        
        print(f"Valid chars ratio: {ratio:.2f}")
        
        # Nếu tỷ lệ ký tự hợp lệ cao (>99%), chọn bảng mã này
        if ratio > 0.99:
            stage2_result = res_str_clean
            used_alphabet = name
            print(f"    [!] Selected {name} alphabet!")
            break
    else:
        print("Failed (invalid chars)")

# Nếu không tìm thấy bảng mã nào hoàn hảo, dùng mặc định (bitcoin) và lọc ký tự
if stage2_result is None:
    print("[-] Không tìm thấy bảng mã Base58 hoàn hảo. Sử dụng Bitcoin alphabet và lọc ký tự rác.")
    res = b58decode_custom(payload_str, ALPHABETS['bitcoin'])
    res_str = res.decode('latin1')
    # Lọc chỉ giữ lại các ký tự có trong bảng mã Base92
    b92_chars = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}`~"
    stage2_result = "".join([c for c in res_str if c in b92_chars])

# 3. Decode Base92
print(f"[*] Decoding Base92 (Input length: {len(stage2_result)})...")
try:
    final_data = base92.b92decode(stage2_result)
    # Nếu kết quả trả về string, encode lại thành bytes
    if isinstance(final_data, str):
        final_data = final_data.encode('latin1')
        
    output_filename = "flag.bin"
    with open(output_filename, "wb") as f:
        f.write(final_data)
        
    print(f"[+] Success! Saved to {output_filename}")
    print(f"[+] Check file type: file {output_filename}")

except Exception as e:
    print(f"[-] Base92 decode failed: {e}")
    print("[-] Dữ liệu có thể vẫn còn rác hoặc sai thuật toán.")