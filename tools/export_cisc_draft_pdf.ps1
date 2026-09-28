param(
    [string]$DocxPath = "D:\Kuliah\RL\SeqSQLi\docs\SeqSQLi_CISC-W26_conference_draft_ko.docx",
    [string]$PdfPath = "D:\Kuliah\RL\SeqSQLi\docs\SeqSQLi_CISC-W26_conference_draft_ko.pdf"
)

$ErrorActionPreference = "Stop"
$word = $null
$document = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $document = $word.Documents.Open($docxPath, $false, $true)
    $document.Repaginate()
    $pages = $document.ComputeStatistics(2)
    $document.ExportAsFixedFormat($pdfPath, 17)
    Write-Output "pages=$pages"
    Write-Output $pdfPath
}
finally {
    if ($null -ne $document) {
        $document.Close($false)
    }
    if ($null -ne $word) {
        $word.Quit()
    }
}
