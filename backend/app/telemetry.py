"""
Omium SDK telemetry module.

Uses the official Omium Python SDK (pip install omium) for tracing,
checkpoints, and W3C Trace Context propagation across async boundaries.

Integrates the Omium SDK's @trace and @checkpoint decorators alongside
raw OpenTelemetry spans so data appears in the app.omium.ai dashboard.
"""

from __future__ import annotations

import functools
import logging
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Dict, Generator, Optional

# Omium SDK — optional; gracefully degrade when not installed or API key absent
try:
    import omium
    from omium import trace as omium_trace_decorator, checkpoint as omium_checkpoint_decorator
    _OMIUM_PKG_AVAILABLE = True
except Exception:  # ImportError or any init-time crash
    omium = None  # type: ignore[assignment]
    omium_trace_decorator = None
    omium_checkpoint_decorator = None
    _OMIUM_PKG_AVAILABLE = False

# Keep OpenTelemetry for low-level span access (backward compat)
from opentelemetry import trace
from opentelemetry.context import attach, detach
from opentelemetry.trace import StatusCode, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from app.config import OMIUM_API_KEY, OMIUM_ENDPOINT, SERVICE_NAME

logger = logging.getLogger(__name__)

_propagator = TraceContextTextMapPropagator()
_tracer: Optional[Tracer] = None
_omium_initialized: bool = False
_execution_id: Optional[str] = None


# ── Bootstrap ────────────────────────────────────────────────────────────────

def init_telemetry() -> Tracer:
    """
    Initialise the Omium SDK and return the project tracer.
    
    This uses the official Omium SDK for tracing and checkpoints,
    which sends data to app.omium.ai for the hackathon dashboard.
    """
    global _tracer, _omium_initialized, _execution_id

    if _tracer is not None:
        return _tracer

    # Initialize the Omium SDK — this sets up tracing, checkpoints,
    # and the connection to the Omium platform automatically.
    # Gracefully skip if the package is missing or OMIUM_API_KEY is unset.
    if _OMIUM_PKG_AVAILABLE and OMIUM_API_KEY:
        try:
            omium.init(
                api_key=OMIUM_API_KEY,
                project=SERVICE_NAME,
                auto_trace=True,
                auto_checkpoint=True,
                checkpoint_strategy="node",
                api_base_url=OMIUM_ENDPOINT if OMIUM_ENDPOINT else None,
                debug=False,
            )
            _omium_initialized = True

            # Set a unique execution ID so all traces from this run are grouped
            _execution_id = f"anvil-{uuid.uuid4().hex[:12]}"
            omium.set_execution_id(_execution_id)

            logger.info(
                "Omium SDK initialised -> %s (project=%s, execution=%s)",
                OMIUM_ENDPOINT or "api.omium.ai",
                SERVICE_NAME,
                _execution_id,
            )
        except Exception as exc:
            logger.warning("Omium SDK init failed (non-fatal): %s", exc)
            _omium_initialized = False
    else:
        logger.info(
            "Omium SDK skipped (package_available=%s, api_key_set=%s) — running without tracing",
            _OMIUM_PKG_AVAILABLE,
            bool(OMIUM_API_KEY),
        )
        _omium_initialized = False

    # Get the underlying OpenTelemetry tracer for manual span creation
    _tracer = trace.get_tracer(SERVICE_NAME)
    return _tracer


def get_tracer() -> Tracer:
    """Return the initialised tracer (calls init_telemetry if needed)."""
    if _tracer is None:
        return init_telemetry()
    return _tracer


def is_omium_active() -> bool:
    """Check if the Omium SDK was successfully initialized."""
    return _omium_initialized


# ── Span helpers ─────────────────────────────────────────────────────────────

@contextmanager
def trace_operation(
    name: str,
    attributes: Optional[Dict[str, Any]] = None,
    kind: trace.SpanKind = trace.SpanKind.INTERNAL,
) -> Generator[trace.Span, None, None]:
    """
    Context manager that creates a child span, attaches attributes,
    and records exceptions automatically.
    
    Also pushes the span through the Omium SDK so it appears in the
    app.omium.ai dashboard.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name, kind=kind) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        try:
            yield span
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            raise


# ── Omium @trace decorator (for agent functions) ────────────────────────────

def omium_traced(name: str = None, span_type: str = "function", **kwargs):
    """
    Decorator that uses the official Omium @trace decorator to send
    function traces to the Omium dashboard.

    Falls back to a no-op if Omium isn't installed or not initialized.
    
    NOTE: Initialization check is deferred to call-time so that decorators
    applied at import-time (before init_telemetry()) still work.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kw):
            if _omium_initialized and omium_trace_decorator is not None:
                try:
                    traced_fn = omium_trace_decorator(
                        name=name or func.__name__,
                        span_type=span_type,
                    )(func)
                    return traced_fn(*args, **kw)
                except Exception as exc:
                    logger.debug("omium_traced call failed for %s: %s", func.__name__, exc)
            return func(*args, **kw)
        return wrapper
    return decorator


def omium_checkpointed(name: str = None, **kwargs):
    """
    Decorator that uses the official Omium @checkpoint decorator.
    Falls back to a no-op if Omium isn't installed or not initialized.
    
    NOTE: Initialization check is deferred to call-time.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kw):
            if _omium_initialized and omium_checkpoint_decorator is not None:
                try:
                    checkpointed_fn = omium_checkpoint_decorator(name=name, **kwargs)(func)
                    return checkpointed_fn(*args, **kw)
                except Exception as exc:
                    logger.debug("omium_checkpointed call failed for %s: %s", func.__name__, exc)
            return func(*args, **kw)
        return wrapper
    return decorator


# ── W3C Trace Context propagation across async / thread boundaries ──────────

def inject_trace_context() -> Dict[str, str]:
    """
    Capture the current span context into a carrier dict
    (W3C traceparent + tracestate) for crossing an async/thread boundary.
    """
    carrier: Dict[str, str] = {}
    _propagator.inject(carrier)
    return carrier


def extract_trace_context(carrier: Dict[str, str]):
    """
    Restore span context from a carrier dict captured on the other side of a
    boundary. Returns a token that must be detached when the work completes.
    """
    ctx = _propagator.extract(carrier)
    return attach(ctx)


def detach_trace_context(token) -> None:
    """Detach a previously attached trace context."""
    detach(token)
