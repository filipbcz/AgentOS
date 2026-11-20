param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$bitmap=[Drawing.Bitmap]::new((Resolve-Path $Path).Path)
try {
    # Reference glyph mask from the visually inspected stage-1 framebuffer.
    $scale=[Math]::Min(4,[Math]::Floor(($bitmap.Width-16)/150))
    $pixels=[Collections.Generic.List[byte]]::new()
    for ($y=0; $y -lt 7; $y++) {
        for ($x=0; $x -lt 150; $x++) {
            $pixels.Add($bitmap.GetPixel((8+$x*$scale),(16+$y*$scale)).R)
        }
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash($pixels.ToArray())).Replace('-','') }
    finally { $sha.Dispose() }
    if ($hash -ne '1B968468FAEA13E9D0F58A36D0E89455C4CE0B79731A43295FCA0460E7FAC9BB') {
        throw "Framebuffer marker mismatch: $Path"
    }
} finally { $bitmap.Dispose() }
