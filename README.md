# Claves Secretas Continuas — README

Pequeña aplicación GUI en Tkinter que genera tokens HMAC-SHA256 basados en una clave semilla (hex) y un contador (paso). Permite generar una clave segura, generar una lista de tokens, guardar los tokens en un archivo y verificar si un token concreto corresponde a la clave y paso indicados.

## Requisitos
- Windows para ejecutar hashes.exe
- Python 3.8+ (Tkinter incluido normalmente) si usas el archivo app.py
- Módulos estándar: tkinter, hmac, hashlib, secrets, os, sys

## Ejecución
Desde PowerShell en la carpeta del proyecto:
```powershell
python .\app.py
```

## Interfaz y uso
- Clave semilla (hex): campo donde pegar o cargar una clave en formato hexadecimal. También puedes pulsar "Generar clave" para crear una clave segura (256 bits — 64 hex chars). La clave generada se copia al portapapeles cuando es posible.
- Número de pasos: número entero > 0 que indica cuántos tokens generar.
- Generar: genera los tokens T1...TN y los muestra en el cuadro de texto.
- Guardar en archivo: guarda los tokens mostrados en un .txt.
- Verificar token: apartado nuevo donde puedes pegar un token (hex) y el número de paso; con la clave semilla presente se comprobará si el token es válido para ese paso.

## Lógica (resumen técnico)
- La función usada para generar un token es:
  - Mensaje: b"counter:{counter}"
  - Algoritmo: HMAC-SHA256 con la clave (bytes) derivada de la clave semilla hex mediante bytes.fromhex()
  - Resultado: se muestra en hex (lowercase)
- Funciones principales en app.py:
  - generar_clave(): genera secrets.token_hex(32) -> 64 hex chars (256 bits).
  - generar(): valida la clave y pasos, genera tokens T1..TN usando generar_token().
  - guardar(): guarda el contenido del área de resultados en un .txt.
  - verificar_hash(): comprueba si un token dado coincide (hmac.compare_digest) con el token esperado para la clave y paso indicados.

## Notas de seguridad y recomendaciones
- Mantén la clave semilla en un lugar seguro; quien la posea puede generar/verificar tokens.
- La clave generada por defecto es de 256 bits (segura para la mayoría de usos).
- No compartas claves ni tokens sensibles por canales inseguros.
- Si necesitas otra longitud de clave, modifica generar_clave() para usar secrets.token_hex(n_bytes).

## Problemas comunes
- Error "la clave debe estar en formato hexadecimal válido": la clave contiene caracteres no hex o tiene longitud impar.
- Si el portapapeles no funciona, la clave aún quedará insertada en el campo "Clave semilla (hex)".