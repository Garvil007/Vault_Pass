@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 ( echo vcvars64 failed & exit /b 1 )
where cl
"%~dp0myenv\Scripts\python.exe" -c "import oqs; print('OQS OK'); print('Kyber1024:', 'Kyber1024' in oqs.get_enabled_kem_mechanisms()); print('Dilithium3:', 'Dilithium3' in oqs.get_enabled_sig_mechanisms())"
