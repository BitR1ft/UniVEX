"use client";

import React, { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Send, Square, Trash2, Loader2 } from "lucide-react";

interface ChatInputProps {
  onSendMessage: (message: string) => void;
  onStop: () => void;
  onClear: () => void;
  isProcessing: boolean;
  disabled?: boolean;
}

export function ChatInput({
  onSendMessage,
  onStop,
  onClear,
  isProcessing,
  disabled = false,
}: ChatInputProps) {
  const [message, setMessage] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (message.trim() && !isProcessing) {
      onSendMessage(message);
      setMessage("");
      
      // Reset textarea height
      if (textareaRef.current) {
        textareaRef.current.style.height = "auto";
      }
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [message]);

  return (
    <Card className="p-4 border-t">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <Textarea
              ref={textareaRef}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask the agent anything... (Shift+Enter for new line)"
              disabled={disabled || isProcessing}
              className="min-h-[60px] max-h-[200px] resize-none"
              rows={2}
            />
          </div>
          <div className="flex gap-2">
            {isProcessing ? (
              <Button
                type="button"
                onClick={onStop}
                variant="destructive"
                size="icon"
                title="Stop"
              >
                <Square className="h-4 w-4" />
              </Button>
            ) : (
              <Button
                type="submit"
                disabled={!message.trim() || disabled}
                size="icon"
                title="Send (Enter)"
              >
                <Send className="h-4 w-4" />
              </Button>
            )}
            <Button
              type="button"
              onClick={onClear}
              variant="outline"
              size="icon"
              title="Clear chat"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <div>Press Enter to send, Shift+Enter for new line</div>
          {isProcessing && (
            <div className="flex items-center gap-2 text-blue-600">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Agent is thinking...</span>
            </div>
          )}
        </div>
      </form>
    </Card>
  );
}
