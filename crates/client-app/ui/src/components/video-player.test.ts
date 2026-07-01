import { test } from 'node:test';
import assert from 'node:assert/strict';
import { streamSrc } from './video-src.ts';

test('streamSrc builds the protocol URL from the file id', () => {
  assert.equal(streamSrc('abc123'), 'stream://media/abc123');
});
