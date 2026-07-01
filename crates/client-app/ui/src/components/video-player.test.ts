import { test } from 'node:test';
import assert from 'node:assert/strict';
import { streamSrc } from './video-src.ts';

test('streamSrc builds the Windows WebView2 custom-protocol URL from the file id', () => {
  assert.equal(streamSrc('abc123'), 'http://stream.localhost/media/abc123');
});
