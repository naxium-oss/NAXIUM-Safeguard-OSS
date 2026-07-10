import { NaxiumSafeguard } from '../src/index.js';

const guard = new NaxiumSafeguard({ securityLevel: 8 });

const toolCall = {
  toolName: 'http_fetch',
  args: { url: 'http://169.254.169.254/latest/meta-data/' },
};

const result = guard.guardToolCall(toolCall, {
  sessionId: 'agent-1',
  protectionKey: 'agent-1', // stable identity you control
});

if (!result.safe) {
  console.log('Tool call blocked:', result.blockedCategories);
} else {
  console.log('Tool call allowed, proceeding...');
}
