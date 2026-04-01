import { defaultOptions } from '../vendor/jsquash-avif/meta.js';
import { initEmscriptenModule } from '../vendor/jsquash-avif/utils.js';
import { threads } from '../vendor/wasm-feature-detect/index.js';

let encoderModulePromise;
let threadSupportPromise;

function isThreadCapableRuntime() {
  return typeof SharedArrayBuffer !== 'undefined' && globalThis.crossOriginIsolated === true;
}

async function canUseThreadedEncoder() {
  if (!threadSupportPromise) {
    threadSupportPromise = (async () => {
      if (!isThreadCapableRuntime()) return false;
      try {
        return await threads();
      } catch {
        return false;
      }
    })();
  }

  return threadSupportPromise;
}

async function getEncoderModule() {
  if (!encoderModulePromise) {
    encoderModulePromise = (async () => {
      const encoderFactory = await canUseThreadedEncoder()
        ? (await import('../vendor/jsquash-avif/codec/enc/avif_enc_mt.js')).default
        : (await import('../vendor/jsquash-avif/codec/enc/avif_enc.js')).default;

      return initEmscriptenModule(encoderFactory);
    })();
  }

  return encoderModulePromise;
}

function normalizeOptions(options = {}) {
  return {
    ...defaultOptions,
    ...options,
    bitDepth: 8,
  };
}

self.addEventListener('message', async (event) => {
  const { height, id, options, pixels, type, width } = event.data || {};
  if (type !== 'encode-avif') return;

  try {
    const module = await getEncoderModule();
    const imageBytes = new Uint8ClampedArray(pixels);
    const encoded = module.encode(
      new Uint8Array(imageBytes.buffer),
      width,
      height,
      normalizeOptions(options),
    );

    self.postMessage({
      id,
      result: encoded.buffer,
      type: 'avif-result',
    }, [encoded.buffer]);
  } catch (error) {
    self.postMessage({
      error: error instanceof Error ? error.message : 'Failed to encode the AVIF image.',
      id,
      type: 'avif-result',
    });
  }
});
