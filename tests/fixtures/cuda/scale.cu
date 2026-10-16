// Scale tide heights on the GPU.
#include <cuda_runtime.h>

__global__ void scale(float *h, float k, int n)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) h[i] *= k;
}

int launch(float *h, int n)
{
    scale<<<(n + 255) / 256, 256>>>(h, 1.5f, n);
    return 0;
}
