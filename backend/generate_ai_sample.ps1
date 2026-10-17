Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.SetOutputToWaveFile('d:\unclone_AgentShield\ai_speech_sample.wav')
$synth.Speak('Aura, please draft a friendly message to my engineering team announcing that version 2.0 is ready for release.')
$synth.Dispose()
Write-Host "Synthesized AI speech successfully: ai_speech_sample.wav"
