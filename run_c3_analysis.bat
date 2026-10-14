@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: Pipeline de Analisis de Cifrado C3 y Vulnerabilidades de Protocolo MU
:: ============================================================================

set "ROOT_DIR=%~dp0"
set "C3_DIR=%ROOT_DIR%c3"

echo ============================================================================
echo   MU PROTOCOL Y ANALISIS DE CIFRADO C3 - PIPELINE
echo ============================================================================
echo.

set "OPTION=%~1"
if not "%OPTION%"=="" goto handle_opt

echo Selecciona la etapa que deseas ejecutar:
echo.
echo   [1] Etapa 1: Inspeccion de Claves y Extraccion de Paquetes (dump_dat + step1)
echo   [2] Etapa 2: Analisis Estatico de DLLs y Binarios (pe_dir + find_exports + npcipher_strings)
echo   [3] Etapa 3: Evaluacion Criptografica C3 (step3 + step4b + step5 + step6 + step7 KPT)
echo   [4] Etapa 4: Laboratorio de Contramedidas y Deteccion (lab.py + c5_test)
echo   [5] Ejecutar TODO el pipeline en orden
echo   [0] Salir
echo.
set /p "OPTION=Elige una opcion (0-5): "

:handle_opt
if "%OPTION%"=="1" goto stage1
if "%OPTION%"=="2" goto stage2
if "%OPTION%"=="3" goto stage3
if "%OPTION%"=="4" goto stage4
if "%OPTION%"=="5" goto all
if "%OPTION%"=="0" goto end
goto invalid

:stage1
echo.
echo ============================================================================
echo  [ETAPA 1] Inspeccion de Claves .dat y Extraccion de Paquetes
echo ============================================================================
echo [*] Ejecutando c3\dump_dat.py...
python "%C3_DIR%\dump_dat.py"
echo.
echo [*] Ejecutando c3\step1_extract.py...
pushd "%C3_DIR%"
python step1_extract.py
popd
echo.
echo [OK] Etapa 1 completada. Flujos c2s.bin y s2c.bin actualizados.
goto finish

:stage2
echo.
echo ============================================================================
echo  [ETAPA 2] Analisis Estatico de Binarios del Cliente
echo ============================================================================
echo [*] Inspeccionando cabecera PE de npcipher.dll (pe_dir.py)...
python "%C3_DIR%\pe_dir.py"
echo.
echo [*] Buscando funciones y cadenas criptograficas en DLLs (find_exports.py)...
python "%C3_DIR%\find_exports.py"
echo.
echo [*] Inspeccionando cadenas en npcipher.dll (npcipher_strings.py)...
python "%C3_DIR%\npcipher_strings.py"
echo.
echo [OK] Etapa 2 completada.
goto finish

:stage3
echo.
echo ============================================================================
echo  [ETAPA 3] Evaluacion de Hipotesis Criptograficas sobre C3
echo ============================================================================
pushd "%C3_DIR%"
echo [*] Comprobando anclas de login y ceros de padding (step3_grid.py)...
python step3_grid.py
echo.
echo [*] Evaluando puntuacion ASCII sobre todos los bloques (step4b_score.py)...
python step4b_score.py
echo.
echo [*] Inspeccionando descifrado de primeros paquetes (step5_inspect.py)...
python step5_inspect.py
echo.
echo [*] Probando intercambio de constantes (step6_swap.py)...
python step6_swap.py
echo.
echo [*] Ataque de texto plano conocido cruzando S2C (step7_kpt.py)...
python step7_kpt.py
popd
echo.
echo [OK] Etapa 3 completada.
goto finish

:stage4
echo.
echo ============================================================================
echo  [ETAPA 4] Validacion de Contramedidas Defensivas y Test Harness (Lab)
echo ============================================================================
pushd "%ROOT_DIR%"
echo [*] Ejecutando pruebas unitarias del canal AEAD C5 (c5_test.py)...
python c5_test.py
echo.
echo [*] Ejecutando simulador de ataques y medicion de deteccion (lab.py)...
python lab.py
popd
echo.
echo [OK] Etapa 4 completada.
goto finish

:all
echo.
echo ============================================================================
echo  EJECUTANDO PIPELINE COMPLETO EN ORDEN
echo ============================================================================

echo --- [1/4] Claves y Extraccion ---
python "%C3_DIR%\dump_dat.py"
pushd "%C3_DIR%"
python step1_extract.py
popd

echo --- [2/4] Analisis de DLLs ---
python "%C3_DIR%\pe_dir.py"
python "%C3_DIR%\find_exports.py"
python "%C3_DIR%\npcipher_strings.py"

echo --- [3/4] Hipotesis C3 y Ataque KPT ---
pushd "%C3_DIR%"
python step3_grid.py
python step4b_score.py
python step5_inspect.py
python step6_swap.py
python step7_kpt.py
popd

echo --- [4/4] Laboratorio Defensivo ---
pushd "%ROOT_DIR%"
python c5_test.py
python lab.py
popd

echo.
echo ============================================================================
echo  PIPELINE COMPLETADO CON EXITO
echo ============================================================================
goto finish

:invalid
echo Opcion invalida.
goto finish

:finish
if "%~1"=="" pause
goto end

:end
