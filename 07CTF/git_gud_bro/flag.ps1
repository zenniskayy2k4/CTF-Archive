# Lấy danh sách các dòng chứa "unreachable blob" từ tệp unreach.txt
$blob_lines = Get-Content -Path "unreach.txt" | Where-Object { $_ -like "*unreachable blob*" }

# Tạo một thư mục để chứa các tệp blob được khôi phục
$outputDir = "recovered_blobs"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

Write-Host "Starting to recover blobs..."

# Lặp qua từng dòng
foreach ($line in $blob_lines) {
    # Tách chuỗi để lấy mã hash
    $hash = ($line -split ' ')[2]
    
    # Bỏ qua hash của tệp rỗng
    if ($hash -eq "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391") {
        continue
    }

    $outputFile = Join-Path $outputDir "blob_$($hash).png"
    
    # Sử dụng git cat-file để lấy nội dung và ghi ra tệp
    # Cần chạy trong cmd.exe để toán tử chuyển hướng '>' hoạt động đúng với dữ liệu nhị phân
    cmd.exe /c "git cat-file blob $hash > $outputFile"
    
    # Đọc 8 byte đầu tiên của tệp vừa tạo
    $fileStream = [System.IO.File]::OpenRead($outputFile)
    $bytes = New-Object byte[] 8
    $fileStream.Read($bytes, 0, 8)
    $fileStream.Close()
    
    # Chuyển 8 byte đó thành chuỗi hex
    $headerHex = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ''
    
    # Header của PNG là 89504E470D0A1A0A
    if ($headerHex -eq "89504E470D0A1A0A") {
        Write-Host "Found potential PNG! Hash: $hash"
        Write-Host "File saved at: $outputFile"
    } else {
        # Nếu không phải PNG, xóa tệp đi
        Remove-Item -Path $outputFile
    }
}

Write-Host "Done."