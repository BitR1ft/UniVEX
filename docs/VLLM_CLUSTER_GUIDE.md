# UniVex vLLM Cluster Guide

**Version:** 2.1.0  
**Author:** BitR1FT  
**Updated:** March 2026

---

## Overview

This guide covers deploying a **vLLM local inference cluster** for air-gapped or privacy-sensitive UniVex deployments. vLLM provides OpenAI-compatible inference with GPU acceleration, enabling UniVex to operate entirely without cloud LLM APIs.

**When to use a local vLLM cluster:**
- Air-gapped environments (government, defence, critical infrastructure)
- Deployments where data must never leave the network perimeter
- Cost reduction for high-volume inference (>100k tokens/day)
- Custom fine-tuned models tailored to penetration testing
- Compliance requirements prohibiting third-party API data processing

---

## GPU Requirements

### Single-Node (Minimum Viable)

| Model Size | VRAM Required | Recommended GPU | Throughput (tokens/s) |
|---|---|---|---|
| 7B (Q4) | 6 GB | RTX 4060 / RTX 3070 | ~30 |
| 7B (FP16) | 14 GB | RTX 4090 (24 GB) | ~80 |
| 13B (FP16) | 28 GB | 2× RTX 4090 | ~50 |
| 34B (FP16) | 70 GB | 4× RTX 4090 | ~30 |
| 70B (FP16) | 140 GB | 4× A100 80GB | ~40 |

### Multi-Node Cluster (Production)

| Configuration | Total VRAM | Recommended For |
|---|---|---|
| 2× RTX 5090 (64 GB) | 64 GB | 34B models, small team (1–5 operators) |
| 4× RTX 5090 (128 GB) | 128 GB | 70B models, medium team (5–20 operators) |
| 2× A100 80GB | 160 GB | 70B models, high availability |
| 4× H100 80GB | 320 GB | 70B–405B models, enterprise |
| 8× H100 80GB | 640 GB | 405B (Llama 3.1), full production |

> **Cost note:** A single RTX 5090 (~$2,000) running `Mistral-7B-Instruct` at ~80 tokens/s can handle ~10 concurrent UniVex operators with sub-second latency.

---

## Model Recommendations for Penetration Testing

| Model | Size | Strengths | UniVex Role Pairing |
|---|---|---|---|
| `Mistral-7B-Instruct-v0.3` | 7B | Fast, good instruction following | recon, report, simple_json |
| `CodeLlama-13b-Instruct` | 13B | Code generation, exploit scripting | coder, generator |
| `Llama-3.1-8B-Instruct` | 8B | Strong general reasoning | planner, adviser |
| `Llama-3.1-70B-Instruct` | 70B | Near-GPT-4 quality | exploit, webapp, reflector |
| `DeepSeek-Coder-V2-Instruct` | 16B | State-of-the-art code/security | coder, exploit, webapp |
| `Qwen2.5-72B-Instruct` | 72B | Multilingual, long context (128k) | all agents, long reports |
| `WizardLM-2-8x22B` | 141B (MoE) | Expert-level security analysis | exploit, adviser |

> ⚠️ Always verify model licences before production deployment. Llama 3.1 requires a Meta licence for commercial use above 700M monthly active users.

---

## Step 1: Install vLLM

### Option A — pip (recommended for single GPU)

```bash
# Python 3.10+ required
pip install vllm

# Verify GPU detection
python -c "import torch; print(torch.cuda.device_count(), 'GPU(s) available')"
```

### Option B — Docker (recommended for production clusters)

```bash
docker pull vllm/vllm-openai:latest

# Or pin to a tested version:
docker pull vllm/vllm-openai:v0.4.3
```

### Option C — Conda (isolated environment)

```bash
conda create -n vllm python=3.11 -y
conda activate vllm
pip install vllm
```

---

## Step 2: Start the vLLM Server

### Single GPU — Quick Start

```bash
# Mistral 7B (fits on RTX 4090, fast)
vllm serve mistralai/Mistral-7B-Instruct-v0.3 \
  --host 0.0.0.0 \
  --port 8080 \
  --tensor-parallel-size 1 \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.90

# Verify the server is ready
curl http://localhost:8080/v1/models | jq '.data[].id'
```

### Multi-GPU (Tensor Parallelism)

```bash
# Llama-3.1-70B across 4× GPUs
vllm serve meta-llama/Meta-Llama-3.1-70B-Instruct \
  --host 0.0.0.0 \
  --port 8080 \
  --tensor-parallel-size 4 \
  --max-model-len 131072 \
  --gpu-memory-utilization 0.95 \
  --enable-chunked-prefill \
  --max-num-batched-tokens 65536
```

### With API Key (secured production endpoint)

```bash
vllm serve mistralai/Mistral-7B-Instruct-v0.3 \
  --host 0.0.0.0 \
  --port 8080 \
  --api-key "$(openssl rand -hex 32)" \
  --ssl-certfile /etc/univex/certs/server.crt \
  --ssl-keyfile /etc/univex/certs/server.key
```

---

## Step 3: Docker Compose Deployment

Create `docker/vllm/docker-compose.vllm.yml`:

```yaml
version: "3.9"

services:
  vllm-server:
    image: vllm/vllm-openai:v0.4.3
    container_name: univex-vllm
    restart: unless-stopped
    runtime: nvidia                  # requires nvidia-container-toolkit
    ports:
      - "8080:8080"
    environment:
      - HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}
      - VLLM_API_KEY=${VLLM_API_KEY}
    volumes:
      - huggingface-cache:/root/.cache/huggingface
      - /etc/univex/certs:/certs:ro
    command: >
      --model mistralai/Mistral-7B-Instruct-v0.3
      --host 0.0.0.0
      --port 8080
      --tensor-parallel-size 1
      --max-model-len 32768
      --gpu-memory-utilization 0.90
      --api-key ${VLLM_API_KEY}
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s   # models take time to load

volumes:
  huggingface-cache:
```

Start:

```bash
HF_TOKEN=<your-hf-token> \
VLLM_API_KEY=$(openssl rand -hex 32) \
docker compose -f docker/vllm/docker-compose.vllm.yml up -d

# Watch model loading progress
docker logs -f univex-vllm
```

---

## Step 4: Configure UniVex to Use vLLM

### Environment Variables

```env
# backend/.env
VLLM_BASE_URL=http://localhost:8080/v1
VLLM_API_KEY=<your-generated-key>   # leave empty for unsecured local

# Set vLLM as the provider for specific agents:
EXPLOIT_PROVIDER=vllm
EXPLOIT_MODEL=mistralai/Mistral-7B-Instruct-v0.3

CODER_PROVIDER=vllm
CODER_MODEL=deepseek-ai/DeepSeek-Coder-V2-Instruct
```

### Provider YAML (`examples/configs/providers/vllm.yaml`)

```yaml
provider: vllm
name: vllm-local
base_url: http://localhost:8080/v1
api_key: ${VLLM_API_KEY}
default_model: ""           # auto-detected from /v1/models
available_models: []        # fetched dynamically
max_tokens: 8192
temperature: 0.7
timeout: 300                # large models can be slow on first request
extra_params:
  top_k: 50
  top_p: 0.95
  repetition_penalty: 1.1
```

### Per-Agent Config (`examples/configs/agents/agents.yaml`)

```yaml
agents:
  # Use vLLM for air-gapped recon
  recon:
    model: mistralai/Mistral-7B-Instruct-v0.3
    provider: vllm
    temperature: 0.1
    max_tokens: 4096

  # Use vLLM for exploit code generation
  coder:
    model: deepseek-ai/DeepSeek-Coder-V2-Instruct
    provider: vllm
    temperature: 0.1
    max_tokens: 8192

  # Keep planner on cloud for best quality
  planner:
    model: gpt-4o
    provider: openai
    temperature: 0.2
    max_tokens: 4096
```

---

## Step 5: Multi-Node Cluster (Ray)

For very large models (70B+) that exceed a single node's VRAM, use Ray for distributed inference:

### Node 1 (Head Node)

```bash
# Install Ray
pip install ray[default]

# Start Ray head
ray start --head --port 6379 --dashboard-host 0.0.0.0

# Launch vLLM with Ray
vllm serve meta-llama/Meta-Llama-3.1-70B-Instruct \
  --host 0.0.0.0 \
  --port 8080 \
  --tensor-parallel-size 4 \
  --pipeline-parallel-size 2 \
  --max-model-len 131072
```

### Node 2+ (Worker Nodes)

```bash
# Join the Ray cluster
ray start --address='<HEAD_NODE_IP>:6379'
```

The head node automatically distributes model shards across all connected nodes.

---

## Performance Tuning

### Throughput Optimisation

```bash
# Enable continuous batching (default in vLLM 0.4+)
# Enable prefix caching for repeated system prompts (saves ~30% VRAM on cache hits)
vllm serve <model> \
  --enable-prefix-caching \
  --enable-chunked-prefill \
  --max-num-batched-tokens 65536 \
  --max-num-seqs 256
```

### Quantisation (for memory-limited deployments)

```bash
# AWQ 4-bit quantisation (2× memory reduction, ~5% quality loss)
vllm serve TheBloke/Mistral-7B-Instruct-v0.3-AWQ \
  --quantization awq \
  --dtype half

# GPTQ quantisation
vllm serve TheBloke/Llama-2-70B-GPTQ \
  --quantization gptq \
  --dtype half
```

### Speculative Decoding (faster for small batch sizes)

```bash
# Use a small draft model to speed up large model inference
vllm serve meta-llama/Meta-Llama-3.1-70B-Instruct \
  --speculative-model meta-llama/Meta-Llama-3.1-8B \
  --num-speculative-tokens 5 \
  --tensor-parallel-size 4
```

---

## Monitoring

### Prometheus Metrics

vLLM exposes metrics at `http://localhost:8080/metrics`:

| Metric | Description |
|---|---|
| `vllm:num_requests_running` | Active inference requests |
| `vllm:num_requests_waiting` | Queued requests |
| `vllm:gpu_cache_usage_perc` | KV-cache utilisation (%) |
| `vllm:generation_tokens_total` | Total generated tokens |
| `vllm:time_to_first_token_seconds` | Time to first token (TTFT) histogram |
| `vllm:time_per_output_token_seconds` | Per-token generation latency |

Add to Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: vllm
    static_configs:
      - targets: ["<VLLM_HOST>:8080"]
        labels:
          model: mistral-7b
```

### Grafana Dashboard

Import the community vLLM dashboard:

```bash
# Dashboard ID: 21473 (vLLM OpenAI-compatible endpoint)
# Navigate to: Grafana → Dashboards → Import → Enter ID: 21473
```

---

## Model Download Management

### Pre-download Before Air-Gapping

```bash
# On internet-connected machine
pip install huggingface_hub

python3 -c "
from huggingface_hub import snapshot_download
# Download model to local cache
snapshot_download(
    repo_id='mistralai/Mistral-7B-Instruct-v0.3',
    local_dir='/data/models/mistral-7b',
    ignore_patterns=['*.bin']  # download .safetensors only
)
"

# Transfer to air-gapped machine
rsync -avz /data/models/mistral-7b airgapped-host:/data/models/

# Run vLLM from local path (no HuggingFace Hub access needed)
vllm serve /data/models/mistral-7b \
  --host 0.0.0.0 \
  --port 8080
```

---

## Fine-Tuning for Penetration Testing (Advanced)

For maximum accuracy on security tasks, fine-tune a base model on penetration testing datasets:

### Recommended Datasets

| Dataset | Source | Focus |
|---|---|---|
| HackTheBox writeups | Community | CTF reasoning, flag finding |
| CVE/NVD descriptions | NIST | Vulnerability analysis |
| OWASP testing guide | OWASP | Web app attack patterns |
| Metasploit module docs | Rapid7 | Exploit knowledge |
| Custom internal findings | Your org | Company-specific TTPs |

### LoRA Fine-Tuning with Axolotl

```bash
pip install axolotl

# Prepare training config
cat > finetune-config.yml << 'EOF'
base_model: mistralai/Mistral-7B-Instruct-v0.3
model_type: MistralForCausalLM
tokenizer_type: LlamaTokenizer

load_in_8bit: false
load_in_4bit: true
strict: false

datasets:
  - path: univex_pentest_dataset.jsonl
    type: alpaca

dataset_shard_num: 1
val_set_size: 0.05
output_dir: ./univex-mistral-pentest

sequence_len: 4096
sample_packing: true

adapter: lora
lora_r: 32
lora_alpha: 64
lora_dropout: 0.05
lora_target_modules:
  - q_proj
  - v_proj
  - k_proj
  - o_proj

gradient_accumulation_steps: 4
micro_batch_size: 2
num_epochs: 3
optimizer: adamw_8bit
lr_scheduler: cosine
learning_rate: 0.0002
EOF

# Run fine-tuning
axolotl train finetune-config.yml
```

### Load Fine-Tuned Model in vLLM

```bash
# Merge LoRA weights first
python3 -c "
from peft import PeftModel, AutoPeftModelForCausalLM
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained('mistralai/Mistral-7B-Instruct-v0.3')
peft_model = PeftModel.from_pretrained(model, './univex-mistral-pentest')
merged = peft_model.merge_and_unload()
merged.save_pretrained('/data/models/univex-mistral-pentest-merged')
"

# Serve merged model
vllm serve /data/models/univex-mistral-pentest-merged \
  --host 0.0.0.0 \
  --port 8080
```

---

## Security Considerations

1. **API key protection** — Always set `VLLM_API_KEY` in production. Without it, anyone on the network can send inference requests.

2. **Network isolation** — The vLLM server should be accessible only from the UniVex backend, not from the public internet. Use a private network or firewall rules.

3. **Model integrity** — Verify model checksums after download, especially in air-gapped transfers:
   ```bash
   sha256sum /data/models/mistral-7b/*.safetensors > /data/models/mistral-7b.sha256
   sha256sum -c /data/models/mistral-7b.sha256
   ```

4. **Prompt injection risk** — Local models do not have built-in safety filters. Enable UniVex's input sanitisation layer (`backend/app/core/`) for all user-provided inputs routed to vLLM.

5. **GPU driver updates** — Keep CUDA drivers current for security patches. Use `nvidia-smi` to verify driver version.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `CUDA out of memory` | Model too large for VRAM | Use quantisation or smaller model |
| `Model not found` | HuggingFace Hub not accessible | Pre-download model, use local path |
| Slow first response | Model loading (cold start) | Wait 60–120s; implement health check |
| High latency under load | Batch size too large | Reduce `max-num-seqs` |
| `Connection refused` | vLLM not bound to 0.0.0.0 | Add `--host 0.0.0.0` flag |
| `NCCL errors` | Multi-GPU communication failure | Check NVLink/PCIe topology with `nvidia-smi topo -m` |

---

## Cluster Checklist

- [ ] GPU drivers installed and verified (`nvidia-smi`)
- [ ] nvidia-container-toolkit installed (for Docker)
- [ ] vLLM installed and model downloaded
- [ ] API key generated and stored securely
- [ ] vLLM server started and responding to `/health`
- [ ] `VLLM_BASE_URL` and `VLLM_API_KEY` set in UniVex backend `.env`
- [ ] Provider YAML updated (`examples/configs/providers/vllm.yaml`)
- [ ] Agent routing configured (`examples/configs/agents/agents.yaml`)
- [ ] Prometheus metrics verified (`/metrics` endpoint)
- [ ] Network firewall rules restricting vLLM to backend only

---

## Related Documentation

- [`docs/WORKER_NODE_GUIDE.md`](WORKER_NODE_GUIDE.md) — Running vLLM on a dedicated worker node
- [`examples/configs/providers/vllm.yaml`](../examples/configs/providers/vllm.yaml) — vLLM provider YAML reference
- [`examples/configs/agents/agents.yaml`](../examples/configs/agents/agents.yaml) — Per-agent model routing
- [`docs/CONFIGURATION_GUIDE.md`](CONFIGURATION_GUIDE.md) — Full environment variable reference
- [vLLM Official Documentation](https://docs.vllm.ai) — Upstream vLLM docs
