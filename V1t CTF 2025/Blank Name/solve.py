def solve_whitespace(code):
    """
    Một trình thông dịch Whitespace đơn giản để giải các bài CTF.
    Nó xử lý các lệnh đẩy số vào stack và in ký tự.
    """
    
    # Dịch mã sang dạng dễ đọc hơn để xử lý
    # Space -> S, Tab -> T, Line Feed -> L
    code = code.replace(' ', 'S').replace('\t', 'T').replace('\n', 'L')
    
    stack = []
    flag = ""
    ip = 0 # Instruction Pointer - Con trỏ lệnh
    
    while ip < len(code):
        # Lệnh: [Space][Space] -> Đẩy một số vào stack
        if code[ip:].startswith('SS'):
            ip += 2 # Bỏ qua 'SS'
            
            # Đọc số
            sign_char = code[ip]
            ip += 1
            
            num_binary_str = ""
            while code[ip] != 'L':
                num_binary_str += code[ip]
                ip += 1
            ip += 1 # Bỏ qua 'L'
            
            # Chuyển đổi nhị phân (S=0, T=1) thành số nguyên
            num_str = num_binary_str.replace('S', '0').replace('T', '1')
            if not num_str:
                # Nếu không có bit nào, số đó là 0
                number = 0
            else:
                number = int(num_str, 2)
            
            if sign_char == 'T':
                number = -number
                
            stack.append(number)
            continue

        # Lệnh: [Tab][Line Feed][Space][Space] -> In ký tự từ stack
        elif code[ip:].startswith('TLSS'):
            ip += 4 # Bỏ qua 'TLSS'
            if stack:
                char_code = stack.pop()
                flag += chr(char_code)
            continue
            
        # Lệnh kết thúc chương trình
        elif code[ip:].startswith('LLL'):
            break
            
        # Bỏ qua các lệnh khác không xác định để giữ cho code đơn giản
        else:
            ip += 1
            
    return flag

# Dữ liệu được trích xuất từ prompt của bạn
whitespace_code = """   			 		 
	
      		   	
	
     			 	  
	
     				 		
	
      		   	
	
     	 					
	
     		   		
	
      		 	  
	
     		 			 
	
     			 	  
	
     	 					
	
     			  		
	
      		  		
	
      		  		
	
     	 					
	
      		 	  
	
     		 			 
	
     				  	
	
     			 	  
	
     		 	   
	
      		   	
	
     		 			 
	
     		  			
	
     					 	
	
  

"""

# Loại bỏ dòng trống đầu tiên nếu có
if whitespace_code.startswith('\n'):
    whitespace_code = whitespace_code[1:]

flag = solve_whitespace(whitespace_code)
print(flag)