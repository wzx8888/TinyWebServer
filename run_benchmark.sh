#!/usr/bin/env bash

set -u

SERVER_PID_FILE="bench_server.pid"
WEBBENCH="./test_pressure/webbench-1.5/webbench"
TARGET="http://127.0.0.1:9006/judge.html"
DURATION=30
RUNS=3
CONCURRENCIES=(100 200 300)
RESULT_DIR="bench_results_$(date +%Y%m%d_%H%M%S)"

if [[ ! -f "$SERVER_PID_FILE" ]]; then
    echo "错误：没有找到 $SERVER_PID_FILE"
    exit 1
fi

SERVER_PID="$(cat "$SERVER_PID_FILE")"

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "错误：服务器进程 $SERVER_PID 不存在"
    exit 1
fi

if [[ ! -x "$WEBBENCH" ]]; then
    echo "错误：Webbench 不存在或不可执行：$WEBBENCH"
    exit 1
fi

HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$TARGET")"

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "错误：压测前健康检查失败，HTTP=$HTTP_CODE"
    exit 1
fi

mkdir -p "$RESULT_DIR"

SUMMARY="$RESULT_DIR/summary.csv"

echo "concurrency,run,duration_s,pages_per_min,qps,bytes_per_sec,succeeded,failed,success_rate,http_after,rss_kb,mem_available_kb" \
    > "$SUMMARY"

echo "========================================"
echo "TinyWebServer 分级压力测试"
echo "服务器 PID：$SERVER_PID"
echo "目标地址：$TARGET"
echo "持续时间：每轮 ${DURATION} 秒"
echo "测试目录：$RESULT_DIR"
echo "========================================"

for concurrency in "${CONCURRENCIES[@]}"; do
    for run in $(seq 1 "$RUNS"); do
        echo
        echo "===== 并发 $concurrency，第 $run/$RUNS 轮 ====="

        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "服务器进程已经退出，停止测试"
            exit 1
        fi

        MEM_AVAILABLE_KB="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"

        echo "当前可用内存：$((MEM_AVAILABLE_KB / 1024)) MiB"

        # 可用内存低于约 250 MiB 时停止，避免无 Swap 环境发生 OOM。
        if (( MEM_AVAILABLE_KB < 256000 )); then
            echo "可用内存不足 250 MiB，为保护服务器停止测试"
            exit 1
        fi

        HTTP_BEFORE="$(curl -s -o /dev/null -w '%{http_code}' \
            --max-time 5 "$TARGET")"

        if [[ "$HTTP_BEFORE" != "200" ]]; then
            echo "压测前健康检查失败，HTTP=$HTTP_BEFORE"
            exit 1
        fi

        PREFIX="$RESULT_DIR/c${concurrency}_run${run}"
        RAW_FILE="${PREFIX}_webbench.txt"
        TOP_FILE="${PREFIX}_top.txt"

        echo "开始时间：$(date '+%F %T')"

        # 每秒记录一次服务器 CPU、内存等资源数据。
        top -b -d 1 -n "$((DURATION + 1))" -p "$SERVER_PID" \
            > "$TOP_FILE" 2>&1 &
        TOP_PID=$!

        # stdbuf 减少 Webbench fork 后重复打印标题的问题。
        stdbuf -oL "$WEBBENCH" \
            -c "$concurrency" \
            -t "$DURATION" \
            "$TARGET" \
            2>&1 | tee "$RAW_FILE"

        WEBBENCH_STATUS=${PIPESTATUS[0]}

        wait "$TOP_PID" 2>/dev/null || true

        if [[ "$WEBBENCH_STATUS" -ne 0 ]]; then
            echo "Webbench 异常退出，状态码：$WEBBENCH_STATUS"
        fi

        PAGES_PER_MIN="$(awk -F'[= ,]+' \
            '/^Speed=/{print $2}' "$RAW_FILE" | tail -1)"

        BYTES_PER_SEC="$(awk -F'[= ,]+' \
            '/^Speed=/{print $4}' "$RAW_FILE" | tail -1)"

        SUCCEEDED="$(awk \
            '/^Requests:/{print $2}' "$RAW_FILE" | tail -1)"

        FAILED="$(awk \
            '/^Requests:/{print $4}' "$RAW_FILE" | tail -1)"

        PAGES_PER_MIN="${PAGES_PER_MIN:-0}"
        BYTES_PER_SEC="${BYTES_PER_SEC:-0}"
        SUCCEEDED="${SUCCEEDED:-0}"
        FAILED="${FAILED:-0}"

        QPS="$(awk -v pages="$PAGES_PER_MIN" \
            'BEGIN {printf "%.2f", pages / 60}')"

        SUCCESS_RATE="$(awk -v ok="$SUCCEEDED" -v fail="$FAILED" '
            BEGIN {
                total = ok + fail;
                if (total == 0) {
                    printf "0.00";
                } else {
                    printf "%.2f", ok * 100 / total;
                }
            }
        ')"

        HTTP_AFTER="$(curl -s -o /dev/null -w '%{http_code}' \
            --max-time 5 "$TARGET")"

        RSS_KB="$(ps -p "$SERVER_PID" -o rss= | tr -d ' ')"
        MEM_AVAILABLE_KB="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"

        echo "$concurrency,$run,$DURATION,$PAGES_PER_MIN,$QPS,$BYTES_PER_SEC,$SUCCEEDED,$FAILED,$SUCCESS_RATE,$HTTP_AFTER,$RSS_KB,$MEM_AVAILABLE_KB" \
            >> "$SUMMARY"

        echo "本轮结果："
        echo "  QPS：$QPS"
        echo "  成功请求：$SUCCEEDED"
        echo "  失败请求：$FAILED"
        echo "  成功率：${SUCCESS_RATE}%"
        echo "  压测后 HTTP：$HTTP_AFTER"
        echo "  服务器 RSS：$((RSS_KB / 1024)) MiB"
        echo "  剩余可用内存：$((MEM_AVAILABLE_KB / 1024)) MiB"

        if [[ "$HTTP_AFTER" != "200" ]]; then
            echo "压测后服务异常，停止后续测试"
            exit 1
        fi

        if (( FAILED > 0 )); then
            echo "检测到失败请求，本轮已经到达或接近稳定性边界"
        fi

        echo "等待 10 秒，让服务器恢复空闲状态……"
        sleep 10
    done
done

echo
echo "========================================"
echo "全部测试完成"
echo "汇总文件：$SUMMARY"
echo "========================================"
cat "$SUMMARY"
