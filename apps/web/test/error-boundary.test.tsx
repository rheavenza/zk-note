/**
 * Error Boundary Component Tests.
 *
 * Verifies:
 * 1. ErrorBoundary renders children normally when no error occurs.
 * 2. ErrorBoundary getDerivedStateFromError sets error state.
 * 3. ErrorBoundary renders friendly fallback UI when error state is active.
 * 4. ErrorBoundary supports custom fallback UI.
 */

import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToString } from "react-dom/server";
import { ErrorBoundary } from "../src/components/ErrorBoundary.js";

test("ErrorBoundary renders children when there is no error", () => {
  const html = renderToString(
    <ErrorBoundary>
      <div id="test-child">Safe Content</div>
    </ErrorBoundary>
  );

  assert.ok(html.includes("Safe Content"));
  assert.ok(html.includes('id="test-child"'));
});

test("ErrorBoundary.getDerivedStateFromError updates state on error", () => {
  const err = new Error("Simulated failure");
  const state = ErrorBoundary.getDerivedStateFromError(err);
  assert.equal(state.hasError, true);
  assert.equal(state.error, err);
});

test("ErrorBoundary renders fallback UI when error state is active", () => {
  const boundary = new ErrorBoundary({ children: <div>Child</div> });
  boundary.state = { hasError: true, error: new Error("Simulated rendering failure") };

  const element = boundary.render() as React.ReactElement;
  const html = renderToString(element);

  assert.ok(html.includes("Something went wrong"));
  assert.ok(html.includes("Simulated rendering failure"));
  assert.ok(html.includes("Try Again"));
  assert.ok(html.includes("Reload Page"));
});

test("ErrorBoundary supports custom fallback UI", () => {
  const boundary = new ErrorBoundary({
    fallback: <div id="custom-fallback">Custom Error View</div>,
    children: <div>Child</div>,
  });
  boundary.state = { hasError: true, error: new Error("Custom fallback test") };

  const element = boundary.render() as React.ReactElement;
  const html = renderToString(element);

  assert.ok(html.includes("Custom Error View"));
  assert.ok(html.includes('id="custom-fallback"'));
});
