#!/bin/bash

orgs=("cloudflare" "fastly" "amazon" "datacamp" "akamai" "oracle")

inputv4GeoLite="GeoLite2-ASN-Blocks-IPv4.csv" #GeoLite2-ASN MaxMind v4
inputv6GeoLite="GeoLite2-ASN-Blocks-IPv6.csv" #GeoLite2-ASN MaxMind v6
inputIPInfo="ipinfo_lite.csv" #IPInfo Lite v4 + v6
inputv4asn="asn-ipv4.csv" #Merged: RouteViews + ASN (afrinic, apnic, arin, lacnic, ripe ncc) + DB-IP ASN Lite v4
inputv6asn="asn-ipv6.csv" #Merged: RouteViews + ASN (afrinic, apnic, arin, lacnic, ripe ncc) + DB-IP ASN Lite v6

# Функция для преобразования IP диапазона в CIDR с помощью Python
converter() {
    local input_file="$1"
    local output_file="$2"
    
    python3 -c "
import ipaddress

with open('$input_file', 'r') as f, open('$output_file', 'w') as out:
    for line in f:
        line = line.strip()
        if line and ',' in line:
            start_ip, end_ip = line.split(',', 1)
            try:
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                for network in ipaddress.summarize_address_range(start, end):
                    out.write(str(network) + '\\n')
            except:
                pass
"
}

echo "Начинаем обработку CSV файлов..."

# Функция для вывода статистики
stats() {
    local source_name="$1"
    local file_prefix="$2"
    echo "=== Статистика для $source_name ==="
    
    for org in "${orgs[@]}"; do
        count=0
        if [ -f "./source/${org}_${file_prefix}.pre" ]; then
            count=$(wc -l < "./source/${org}_${file_prefix}.pre" 2>/dev/null || echo 0)
        fi
        printf "  %-15s: %d записей\n" "$org" "$count"
    done
    echo
}

# Создаем директорию source и release если их нет
mkdir -p ./source
mkdir -p ./release

# Обработка MaxMind IPv4 - один проход по файлу (пропускаем заголовок)
echo "Обработка MaxMind IPv4..."
for org in "${orgs[@]}"; do
    awk -F',' -v org="$org" 'NR>1 && tolower($3) ~ org {print $1}' "$inputv4GeoLite" >> "./source/${org}_maxmind.pre"
done

# Обработка MaxMind IPv6 - один проход по файлу (пропускаем заголовок)
echo "Обработка MaxMind IPv6..."
for org in "${orgs[@]}"; do
    awk -F',' -v org="$org" 'NR>1 && tolower($3) ~ org {print $1}' "$inputv6GeoLite" >> "./source/${org}_maxmind.pre"
done

stats "MaxMind" "maxmind"

# Обработка IPInfo - один проход по файлу (пропускаем заголовок)
echo "Обработка IPInfo..."
for org in "${orgs[@]}"; do
    awk -F',' -v org="$org" 'NR>1 && tolower($7) ~ org {print $1}' "$inputIPInfo" >> "./source/${org}_ipinfo.pre"
done

stats "IPInfo" "ipinfo"

# Обработка ASN IPv4 - один проход по файлу с конвертацией диапазонов
echo "Обработка ASN IPv4..."
for org in "${orgs[@]}"; do
    awk -F',' -v org="$org" 'tolower($4) ~ org {print $1 "," $2}' "$inputv4asn" >> "./source/${org}_asn_ranges.pre"
done

# Обработка ASN IPv6 - один проход по файлу с конвертацией диапазонов
echo "Обработка ASN IPv6..."
for org in "${orgs[@]}"; do
    awk -F',' -v org="$org" 'tolower($4) ~ org {print $1 "," $2}' "$inputv6asn" >> "./source/${org}_asn_ranges.pre"
done

# Выводим статистику по диапазонам ASN
echo "=== Статистика по диапазонам ASN ==="
for org in "${orgs[@]}"; do
    count=0
    if [ -f "./source/${org}_asn_ranges.pre" ]; then
        count=$(wc -l < "./source/${org}_asn_ranges.pre" 2>/dev/null || echo 0)
    fi
    printf "  %-15s: %d диапазонов\n" "$org" "$count"
done
echo

# КОНВЕРТАЦИЯ ДИАПАЗОНОВ В CIDR С ПОМОЩЬЮ PYTHON (ОПТИМИЗИРОВАННАЯ)
echo "Конвертация IP диапазонов в CIDR..."
for org in "${orgs[@]}"; do
    if [ -f "./source/${org}_asn_ranges.pre" ] && [ -s "./source/${org}_asn_ranges.pre" ]; then
        range_count=$(wc -l < "./source/${org}_asn_ranges.pre")
        
        # Используем Python для пакетной конвертации всех диапазонов
        converter "./source/${org}_asn_ranges.pre" "./source/${org}_asn.pre"
        
        # Удаляем дубликаты и пустые строки
        sort -u "./source/${org}_asn.pre" | sed '/^$/d' > "./source/${org}_asn_sorted.pre"
        mv "./source/${org}_asn_sorted.pre" "./source/${org}_asn.pre"
        
        cidr_count=$(wc -l < "./source/${org}_asn.pre" 2>/dev/null || echo 0)
        echo "Конвертация для $org ($range_count диапазонов → $cidr_count CIDR блоков)"
        
        # Удаляем временные файлы
        rm -f "./source/${org}_asn_ranges.pre"
    fi
done

# Объединяем все файлы для каждой организации в один org.lst
echo "Объединяем файлы для каждой организации..."

for org in "${orgs[@]}"; do
    echo "Создание ${org}.lst..."
    
    # Считаем записи из каждого источника для статистики
    maxmind_count=0
    ipinfo_count=0
    asn_count=0
    
    if [ -f "./source/${org}_maxmind.pre" ] && [ -s "./source/${org}_maxmind.pre" ]; then
        maxmind_count=$(wc -l < "./source/${org}_maxmind.pre")
    fi
    if [ -f "./source/${org}_ipinfo.pre" ] && [ -s "./source/${org}_ipinfo.pre" ]; then
        ipinfo_count=$(wc -l < "./source/${org}_ipinfo.pre")
    fi
    if [ -f "./source/${org}_asn.pre" ] && [ -s "./source/${org}_asn.pre" ]; then
        asn_count=$(wc -l < "./source/${org}_asn.pre")
    fi
    
    # Объединяем все три файла, удаляя пустые строки и дубликаты
    {
        if [ $maxmind_count -gt 0 ]; then
            cat "./source/${org}_maxmind.pre" | sed '/^$/d'
        fi
        
        if [ $ipinfo_count -gt 0 ]; then
            cat "./source/${org}_ipinfo.pre" | sed '/^$/d'
        fi
        
        if [ $asn_count -gt 0 ]; then
            cat "./source/${org}_asn.pre" | sed '/^$/d'
        fi
    } | sed '/^$/d' | sort -u > "./source/${org}.lst"
    
    final_count=$(wc -l < "./source/${org}.lst" 2>/dev/null || echo 0)
    echo "  → ${org}.lst: $final_count записей (MaxMind: $maxmind_count, IPInfo: $ipinfo_count, ASN: $asn_count)"
    
    # Очищаем временные файлы
    rm -f "./source/${org}_maxmind.pre" "./source/${org}_ipinfo.pre" "./source/${org}_asn.pre"
done

# Объединяем все файлы в один
echo "Создание общего файла merged.pre с несхлопнутыми CIDR блоками (полуфабрикат)..."
cat ./source/*.lst > ./source/merged.pre 2>/dev/null

total_all=$(wc -l < ./source/merged.pre 2>/dev/null || echo 0)
echo "Всего несхлопнутых CIDR блоков: $total_all"
echo
echo "Схлопывание CIDR блоков и дедупликация..."
echo

python3 optimize.py ips source/merged.pre source/merged.sum

cp source/merged.sum release/merged.sum

total_all_final=$(wc -l < ./release/merged.sum 2>/dev/null || echo 0)
echo "✅ Итоговое количество CIDR блоков: $total_all_final"

rm -rf *.csv
rm -rf ./source/*.pre
echo
echo "✅ Все файлы объединены и временные файлы очищены! Готово!"