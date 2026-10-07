import React, { useState, useEffect } from 'react';
import { Clock } from 'lucide-react';

export function TimerCountdown({ expiresAt, onExpire }) {
  const [timeLeft, setTimeLeft] = useState(calculateTimeLeft());

  function calculateTimeLeft() {
    const diff = new Date(expiresAt).getTime() - new Date().getTime();
    if (diff <= 0) return { total: 0, hours: 0, minutes: 0, seconds: 0 };
    return {
      total: diff,
      hours: Math.floor((diff / (1000 * 60 * 60)) % 24),
      minutes: Math.floor((diff / 1000 / 60) % 60),
      seconds: Math.floor((diff / 1000) % 60)
    };
  }

  useEffect(() => {
    const timer = setInterval(() => {
      const remaining = calculateTimeLeft();
      setTimeLeft(remaining);
      if (remaining.total <= 0) {
        clearInterval(timer);
        if (onExpire) onExpire();
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [expiresAt]);

  const pad = (n) => String(n).padStart(2, '0');

  const isWarning = timeLeft.total < 10 * 60 * 1000; // less than 10 mins

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'var(--font-mono)' }}>
      <Clock size={16} color={isWarning ? '#f87171' : '#38bdf8'} />
      <span style={{ fontSize: '0.95rem', fontWeight: '700', color: isWarning ? '#f87171' : '#38bdf8' }}>
        {timeLeft.total <= 0 ? (
          'EXPIRED'
        ) : (
          `${pad(timeLeft.hours)}:${pad(timeLeft.minutes)}:${pad(timeLeft.seconds)}`
        )}
      </span>
    </div>
  );
}
