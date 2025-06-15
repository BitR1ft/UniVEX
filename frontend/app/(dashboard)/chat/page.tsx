"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { ChatWindow } from "@/components/chat/ChatWindow";
import { ChatInput } from "@/components/chat/ChatInput";
import { PhaseIndicator } from "@/components/chat/PhaseIndicator";

interface Message {
  id: string;
  type: "user" | "agent" | "thought" | "tool" | "error";
  content: string;
  timestamp: Date;
}

type Phase = "informational" | "exploitation" | "post_exploitation" | "complete";

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentPhase, setCurrentPhase] = useState<Phase>("informational");
  const [threadId, setThreadId] = useState<string>("");
  const wsRef = useRef<WebSocket | null>(null);
  const clientIdRef = useRef<string>("");

  useEffect(() => {
    // Generate client ID and thread ID
    clientIdRef.current = `client-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
    setThreadId(`thread-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`);

    // Connect to WebSocket
    connectWebSocket();

    return () => {
      // Cleanup WebSocket on unmount
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const connectWebSocket = () => {
    const wsUrl = `ws://localhost:8000/api/agent/ws/${clientIdRef.current}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log("WebSocket connected");
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      } catch (error) {
        console.error("Error parsing WebSocket message:", error);
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      addMessage({
        type: "error",
        content: "WebSocket connection error. Please refresh the page.",
      });
    };

    ws.onclose = () => {
      console.log("WebSocket disconnected");
    };

    wsRef.current = ws;
  };

  const handleWebSocketMessage = (data: any) => {
    console.log("WebSocket message:", data);

    switch (data.type) {
      case "connected":
        console.log("Connected to agent:", data.client_id);
        break;

      case "agent_update":
        // Handle agent state updates
        const stateUpdate = data.data?.state_update || {};
        
        // Extract and display thought
        if (stateUpdate.messages) {
          const lastMessage = Array.isArray(stateUpdate.messages) 
            ? stateUpdate.messages[stateUpdate.messages.length - 1] 
            : null;
          
          if (lastMessage && typeof lastMessage === 'string') {
            if (lastMessage.startsWith("THOUGHT:")) {
              addMessage({
                type: "thought",
                content: lastMessage.replace("THOUGHT:", "").trim(),
              });
            }
          }
        }
        
        // Display tool output
        if (stateUpdate.observation) {
          addMessage({
            type: "tool",
            content: stateUpdate.observation,
          });
        }
        
        // Update phase if changed
        if (stateUpdate.current_phase) {
          setCurrentPhase(stateUpdate.current_phase);
        }
        break;

      case "agent_complete":
        setIsProcessing(false);
        // Extract final agent response
        if (messages.length > 0) {
          const lastMsg = messages[messages.length - 1];
          if (lastMsg.type !== "agent" && lastMsg.type !== "user") {
            // Add a completion message if we don't have a proper response
            addMessage({
              type: "agent",
              content: "Processing complete.",
            });
          }
        }
        break;

      case "error":
        setIsProcessing(false);
        addMessage({
          type: "error",
          content: data.message || "An error occurred",
        });
        break;

      case "pong":
        // Heartbeat response
        break;

      default:
        console.log("Unknown message type:", data.type);
    }
  };

  const addMessage = (message: Omit<Message, "id" | "timestamp">) => {
    const newMessage: Message = {
      ...message,
      id: `msg-${Date.now()}-${Math.random()}`,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, newMessage]);
  };

  const handleSendMessage = useCallback(
    (content: string) => {
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
        addMessage({
          type: "error",
          content: "Not connected to agent. Please refresh the page.",
        });
        return;
      }

      // Add user message to UI
      addMessage({
        type: "user",
        content,
      });

      // Send message to agent via WebSocket
      wsRef.current.send(
        JSON.stringify({
          type: "chat",
          message: content,
          thread_id: threadId,
          model_provider: "openai",
          model_name: "gpt-4",
        })
      );

      setIsProcessing(true);
    },
    [threadId]
  );

  const handleStop = useCallback(() => {
    setIsProcessing(false);
    // TODO: Implement stop functionality on backend
    addMessage({
      type: "agent",
      content: "Stopped by user.",
    });
  }, []);

  const handleClear = useCallback(() => {
    setMessages([]);
    setCurrentPhase("informational");
    // Generate new thread ID for fresh conversation
    setThreadId(`thread-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`);
  }, []);

  return (
    <div className="h-full flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">AI Agent</h1>
        <p className="text-muted-foreground">
          Interact with the autonomous penetration testing agent
        </p>
      </div>

      <PhaseIndicator currentPhase={currentPhase} />

      <div className="flex-1 flex flex-col gap-4 min-h-0">
        <ChatWindow messages={messages} isProcessing={isProcessing} />
        <ChatInput
          onSendMessage={handleSendMessage}
          onStop={handleStop}
          onClear={handleClear}
          isProcessing={isProcessing}
        />
      </div>
    </div>
  );
}
