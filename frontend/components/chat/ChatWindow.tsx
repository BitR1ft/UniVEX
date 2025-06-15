"use client";

import React, { useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { MessageBubble } from "./MessageBubble";
import { Loader2 } from "lucide-react";

interface Message {
  id: string;
  type: "user" | "agent" | "thought" | "tool" | "error";
  content: string;
  timestamp: Date;
}

interface ChatWindowProps {
  messages: Message[];
  isProcessing: boolean;
}

export function ChatWindow({ messages, isProcessing }: ChatWindowProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isProcessing]);

  return (
    <Card className="flex-1 overflow-hidden flex flex-col">
      <div className="p-4 border-b bg-muted/50">
        <h2 className="text-lg font-semibold">AI Agent Chat</h2>
        <p className="text-sm text-muted-foreground">
          Chat with the autonomous penetration testing agent
        </p>
      </div>
      
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto p-4 space-y-4"
      >
        {messages.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center space-y-3">
              <div className="text-6xl">🤖</div>
              <div className="text-lg font-medium">Start a conversation</div>
              <div className="text-sm max-w-md">
                Ask the agent to help with reconnaissance, exploitation, or
                post-exploitation tasks. The agent will use its tools and
                reasoning to assist you.
              </div>
            </div>
          </div>
        ) : (
          <>
            {messages.map((message) => (
              <MessageBubble key={message.id} message={message} />
            ))}
            {isProcessing && (
              <div className="flex items-center gap-2 text-muted-foreground p-4">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span className="text-sm">Agent is processing...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>
    </Card>
  );
}
