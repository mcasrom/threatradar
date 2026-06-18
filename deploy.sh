#!/bin/bash

# Salir inmediatamente si ocurre un error
set -e

# Mensaje de commit por defecto si no se pasa ninguno como argumento
COMMIT_MSG="${1:-"Fix: Actualización automática y limpieza de configuración"}"

echo "🔄 Iniciando despliegue hacia GitHub..."

# Añadir todos los cambios
git add .

# Hacer el commit con el mensaje
git commit -m "$COMMIT_MSG"

# Empujar a la rama principal
git push origin main

echo "🚀 ¡Despliegue completado con éxito en GitHub!"
