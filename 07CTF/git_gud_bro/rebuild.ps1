# The known hash of the first PNG chunk (the one with the header).
$known_blob_hash = "16621ed2aed430014a51eb0ed4b21524bb014c24"

# Get all unreachable commit hashes, ignoring reflogs.
$commit_hashes = git fsck --unreachable --no-reflogs | Where-Object { $_ -like "*unreachable commit*" } | ForEach-Object { ($_ -split ' ')[2] }

Write-Host "Checking $($commit_hashes.Count) unreachable commits to find the one containing blob hash: $known_blob_hash"

$correctBlobs = $null

# Loop through each commit to find the one that contains our known blob.
foreach ($commit_hash in $commit_hashes) {
    # Get the tree hash from the commit object.
    $tree_hash = (git cat-file -p $commit_hash | Select-String -Pattern '^tree' | ForEach-Object { ($_ -split ' ')[1] })
    
    # Get the content of that tree.
    $tree_content = git cat-file -p $tree_hash
    
    # Check if this tree contains our known blob.
    if ($tree_content -like "*$known_blob_hash*") {
        Write-Host "Found the correct tree! Tree hash: $tree_hash (from commit $commit_hash)"
        $correctBlobs = $tree_content -split "`n" | Where-Object { $_ -ne "" }
        break
    }
}

if ($null -eq $correctBlobs) {
    Write-Host "Error: Could not find any commit/tree containing the known blob hash '$known_blob_hash'."
    exit
}

# Parse and sort the blobs by their filename (00, 01, 02, ...).
$sortedBlobs = $correctBlobs | ForEach-Object {
    $parts = $_ -split '\s+'
    [pscustomobject]@{
        Mode = $parts[0]
        Type = $parts[1]
        Hash = $parts[2]
        Name = $parts[3]
    }
} | Sort-Object Name

Write-Host "Found $($sortedBlobs.Count) chunks. Starting to append in filename order..."

# Byte list to store the final file content.
$finalFileContent = New-Object System.Collections.Generic.List[byte]

# Temporary file for capturing binary output
$tempFile = [System.IO.Path]::GetTempFileName()

# Loop through the sorted blobs and append their content.
foreach ($blob in $sortedBlobs) {
    # Use cmd.exe to correctly pipe binary output to a temporary file
    cmd.exe /c "git cat-file blob $($blob.Hash) > $tempFile"
    # Read the raw bytes from the temporary file and add to our list
    $blobContent = [System.IO.File]::ReadAllBytes($tempFile)
    $finalFileContent.AddRange($blobContent)
}

# Clean up the temporary file
Remove-Item $tempFile

# Write the resulting byte array to the final PNG file.
$outputFileName = "final_flag.png"
[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot $outputFileName), $finalFileContent.ToArray())

Write-Host "Done! Image file created: $outputFileName"