#!/bin/bash
# 用于办公区网络

# FOR OPENWRT
# opkg install openssl-util
# opkg install coreutils-base64
# opkg install xxd
# opkg install bash
# ############
# Third-Party Binaries Used: openssl, base64, xxd
# ############

USERNAME=""
PASSWORD=""

md5() {
    RES=$(echo -n "$1" | openssl md5 -hmac "$2")
    ENC=$(echo "$RES" | awk '{print $2}')
    echo "$ENC"
}

sha1() {
    RES=$(echo -n "$1" | openssl sha1)
    ENC=$(echo "$RES" | awk '{print $2}')
    echo "$ENC"
}

fun_s(){
    local original_string="$1"
    local addLen="$2"
    local a=()
    # Transfer String to Int Array
    for ((i = 0; i < ${#original_string}; i++)); do
        local char=${original_string:$i:1}
        local ascii_code=$(( $(printf '%d' "'$char") ))
        a+=("$ascii_code")
    done
    # Combine Array
    local combined_array=()
    for (( i = 0; i < ${#a[@]}; i += 4 )); do
        local result=0
        local local_elements=("${a[@]:i:4}")
        for (( j = 0; j < ${#local_elements[@]}; j++ )); do
            local num=${local_elements[j]}
            if (( num > 255 )); then
                num=$((num & 255))
            fi
            local shifted_num=$((num * 256 ** j))
            result=$((result | shifted_num))
        done
        combined_array+=("$result")
    done
    # Add Element for Length
    if [ "$addLen" = "true" ]; then
        local string_length=${#original_string}
        combined_array+=("$string_length")
    fi
    echo ${combined_array[*]}
}

fun_l(){
    local a=("$@")
    local withLen=${a[-1]}
    a=("${a[@]:0:${#a[@]}-1}")
    local result=()
    # Expand Array
    for num in "${a[@]}"; do
        for ((i = 0; i < 4; i++)); do
            shifted=$((num >> (8 * i)))
            byte=$((shifted & 255))
            result+=("$byte")
        done
    done
    # Remove Element for Length
    if [ "$withLen" = "true" ]; then
        result=("${result[@]:0:${#result[@]}-1}")
    fi

    echo "${result[*]}"
}

encode() { 
# Input: string str, string key - Output: IntArray 
    local str="$1"
    local key="$2"
    local strArr=($(fun_s $str true))
    local keyArr=($(fun_s $key false))

    local n=$((${#strArr[@]} - 1))
    local z=${strArr[n]}
    local y=${strArr[0]}
    local c=$((0x86014019 | 0x183639A0))
    local m=0
    local e=0
    local p=0
    local iter=$((6 + 52 / (n + 1)))
    local d=0

    while true; do
        iter=$((iter - 1))
        d=$(((d + c) & 4294967295))
        e=$((d >> 2 & 3))
        for ((p = 0; p < n; p++)); do
            y=${strArr[p + 1]}
            m=$(( ((z >> 5 & 4294967295) ^ ((y << 2 & 4294967295))) & 4294967295 ))
            m=$(( ((m + (((y >> 3) ^ ((z << 4 & 4294967295))) ^ (d ^ y & 4294967295)) )) & 4294967295 ))
            m=$(( (m + (keyArr[((p & 3) ^ e)] ^ z)) & 4294967295 ))
            strArr[p]=$(((strArr[p] + m & 4294967295) ))
            z=${strArr[p]}
        done
        y=${strArr[0]}
        m=$(( ((z >> 5 & 4294967295) ^ ((y << 2 & 4294967295))) & 4294967295 ))
        m=$(( ((m + (((y >> 3) ^ ((z << 4 & 4294967295))) ^ (d ^ y & 4294967295)) )) & 4294967295 ))
        m=$(( (m + (keyArr[((n & 3) ^ e)] ^ z)) & 4294967295 ))
        strArr[n]=$(((strArr[n] + m & 4294967295) ))
        z=${strArr[n]}
        if ((0 >= iter)); then
            break
        fi
    done

    echo $(fun_l ${strArr[*]} false)
}

custom_base64() {
    local byte_array=("$@")
    # Convert byte array to hex string
    local hex_string=$(printf "%02x" "${byte_array[@]}" | tr -d ' ')
    # Convert hex string to binary form using xxd
    local base64_encoded=$(echo -n "$hex_string" | xxd -r -p | base64 -w 0)
    # Custom Alphabet
    local mapping="LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="
    local original="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    local output_string=""
    for (( i = 0; i < ${#base64_encoded}; i++ )); do
        local char="${base64_encoded:$i:1}"
        local index=$(expr index "$original" {$char})
        local new_char="${mapping:index-1:1}"
        output_string+="$new_char"
    done
    echo $output_string
}

####### Start Script
# echo "开始检测网络认证状态"
logger -t szu-login "开始检测网络认证状态"

ONLINE_STATE=$(curl -s https://net.szu.edu.cn/cgi-bin/rad_user_info)

if [ "$ONLINE_STATE" == "not_online_error" ]; then
    logger -t szu-login "尚未认证，尝试自动认证"
    # Step 1. Get Hash Salt and IP Address
    CALLBACK=$(date +"%Y%m%d_%H%M%S")
    # `curl -k`` To allow untrusted SSL cert
    CHALLENGE_STATUS=$(curl -s -G --data-urlencode "callback=$CALLBACK" -d "username=$USERNAME" https://net.szu.edu.cn/cgi-bin/get_challenge)

    TOKEN=$(echo "$CHALLENGE_STATUS" | grep -o '"challenge":"[^"]*' | awk -F'"' '{print $4}')
    IP_ADDR=$(echo "$CHALLENGE_STATUS" | grep -o '"client_ip":"[^"]*' | awk -F'"' '{print $4}') 
    RES=$(echo "$CHALLENGE_STATUS" | grep -o '"res":"[^"]*' | awk -F'"' '{print $4}')

    if [ "$RES" != "ok" ]; then
        # echo "认证失败：无法获得Challenge -> ${RES}"
        logger -t szu-login "认证失败：无法获得Challenge -> ${RES}"
        exit 1
    fi

    # Step 2. Compose Argument and Send Request
    ENCPWD=$(md5 "$PASSWORD" "$TOKEN")
    INFO="{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\",\"ip\":\"$IP_ADDR\",\"acid\":\"12\",\"enc_ver\":\"srun_bx1\"}"

    INFO={SRBX1}$(custom_base64 $(encode $INFO $TOKEN))
    STR="$TOKEN$USERNAME$TOKEN$ENCPWD${TOKEN}12$TOKEN$IP_ADDR${TOKEN}200${TOKEN}1${TOKEN}$INFO"
    ENCSTR=$(sha1 "$STR")
    # `curl -k`` To allow untrusted SSL cert
    LOGIN_STATUS=$(curl -s -G --data-urlencode "callback=$CALLBACK" -d "action=login" -d "username=$USERNAME" -d "password={MD5}$ENCPWD" -d "chksum=$ENCSTR" --data-urlencode "info=${INFO}" -d "ac_id=12" -d "ip=$IP_ADDR" -d "n=200" -d "type=1" https://net.szu.edu.cn/cgi-bin/srun_portal)

    RES=$(echo "$LOGIN_STATUS" | grep -o '"res":"[^"]*' | awk -F'"' '{print $4}')

    if [ "$RES" != "ok" ]; then
        # echo "认证失败 -> ${RES}"
        logger -t szu-login "认证失败 -> ${RES}"
        exit 1
    fi
    # echo "自动认证成功"
    logger -t szu-login "自动认证成功"
else
    # echo "已认证"
    logger -t szu-login "检测到已经认证"
fi