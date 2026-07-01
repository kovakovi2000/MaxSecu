import { test } from 'node:test';
import assert from 'node:assert/strict';
import { streamSrc, previewSrc } from './video-src.ts';

test('streamSrc builds the Windows WebView2 custom-protocol URL from the file id', () => {
  assert.equal(streamSrc('abc123'), 'http://stream.localhost/media/abc123');
});

test('previewSrc builds the preview-namespace custom-protocol URL from the job id', () => {
  assert.equal(previewSrc('job-xyz'), 'http://stream.localhost/preview/job-xyz');
});
