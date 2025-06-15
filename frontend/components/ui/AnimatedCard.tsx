'use client';

import React, { useRef, useState } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'framer-motion';
import { cn } from '@/lib/utils';

interface AnimatedCardProps {
  children: React.ReactNode;
  className?: string;
  glowColor?: 'cyan' | 'green' | 'amber' | 'none';
  tiltEffect?: boolean;
  onClick?: () => void;
  as?: keyof JSX.IntrinsicElements;
}

export function AnimatedCard({
  children,
  className,
  glowColor = 'cyan',
  tiltEffect = true,
  onClick,
  as: Tag = 'div',
}: AnimatedCardProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const mouseXSpring = useSpring(x);
  const mouseYSpring = useSpring(y);

  const rotateX = useTransform(mouseYSpring, [-0.5, 0.5], ['8deg', '-8deg']);
  const rotateY = useTransform(mouseXSpring, [-0.5, 0.5], ['-8deg', '8deg']);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!tiltEffect || !ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    x.set((e.clientX - rect.left) / rect.width - 0.5);
    y.set((e.clientY - rect.top) / rect.height - 0.5);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
    setIsHovered(false);
  };

  const glowMap = {
    cyan: 'hover:shadow-glow-cyan',
    green: 'hover:shadow-glow-green',
    amber: 'hover:shadow-glow-amber',
    none: '',
  };

  return (
    <motion.div
      ref={ref}
      style={tiltEffect ? { rotateX, rotateY, transformStyle: 'preserve-3d' } : undefined}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={handleMouseLeave}
      onClick={onClick}
      className={cn(
        'relative rounded-lg border border-border bg-card transition-all duration-300',
        'cursor-pointer',
        glowMap[glowColor],
        'border-shimmer',
        className,
      )}
    >
      {/* Shimmer overlay */}
      {isHovered && (
        <motion.div
          className="absolute inset-0 rounded-lg pointer-events-none"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          style={{
            background: 'linear-gradient(135deg, rgba(0,212,255,0.04) 0%, transparent 60%)',
          }}
        />
      )}
      {children}
    </motion.div>
  );
}
