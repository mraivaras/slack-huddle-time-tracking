export default {
    async fetch(request, env) {
        // Verify request is from Slack
        const signature = request.headers.get('X-Slack-Signature');
        const timestamp = request.headers.get('X-Slack-Request-Timestamp');

        if (!signature || !timestamp) {
            return new Response('Unauthorized', { status: 401 });
        }

        // Parse the request
        const body = await request.text();

        // Verify Slack signature (important for security)
        const isValid = await verifySlackSignature(
            signature,
            timestamp,
            body,
            env.SLACK_SIGNING_SECRET
        );

        if (!isValid) {
            return new Response('Invalid signature', { status: 401 });
        }

        const payload = JSON.parse(body);

        // Handle URL verification challenge
        if (payload.type === 'url_verification') {
            return new Response(JSON.stringify({ challenge: payload.challenge }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Handle events
        if (payload.type === 'event_callback') {
            const event = payload.event;

            if (event.type === 'user_huddle_changed') {
                await handleHuddleChange(event, env);
            }
        }

        return new Response('OK', { status: 200 });
    }
};

async function handleHuddleChange(event, env) {
    const user = event.user;
    const huddleState = user.profile?.huddle_state;
    const callId = user.profile?.huddle_state_call_id;

    if (!callId) return;

    const huddleKey = `huddle:${callId}`;

    if (huddleState === 'in_a_huddle') {
        // User joined huddle
        const existingData = await env.HUDDLES.get(huddleKey);

        if (!existingData) {
            // New huddle started
            const huddleData = {
                startTime: Date.now(),
                users: [user.id],
                startedBy: user.id
            };
            await env.HUDDLES.put(huddleKey, JSON.stringify(huddleData));
        } else {
            // Add user to existing huddle
            const huddleData = JSON.parse(existingData);
            if (!huddleData.users.includes(user.id)) {
                huddleData.users.push(user.id);
                await env.HUDDLES.put(huddleKey, JSON.stringify(huddleData));
            }
        }

        const test = await env.HUDDLES.get(huddleKey);
        await sendSlackMessage(
            env.SLACK_BOT_TOKEN,
            huddleData.startedBy,
            `${JSON.parse(test)}`
        );
    } else {
        // User left huddle
        const existingData = await env.HUDDLES.get(huddleKey);

        if (existingData) {
            const huddleData = JSON.parse(existingData);
            huddleData.users = huddleData.users.filter(id => id !== user.id);

            if (huddleData.users.length === 0) {
                // Huddle ended - calculate duration and notify
                const endTime = Date.now();
                const duration = Math.floor((endTime - huddleData.startTime) / 1000);
                const durationFormatted = formatDuration(duration);

                // Send message to user
                await sendSlackMessage(
                    env.SLACK_BOT_TOKEN,
                    huddleData.startedBy,
                    `📞 Your huddle just ended! Duration: *${durationFormatted}*`
                );

                // Clean up
                await env.HUDDLES.delete(huddleKey);
            } else {
                // Update huddle with remaining users
                await env.HUDDLES.put(huddleKey, JSON.stringify(huddleData));
            }
        }
    }
}

async function sendSlackMessage(token, channel, text) {
    const response = await fetch('https://slack.com/api/chat.postMessage', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            channel: channel,
            text: text,
            blocks: [
                {
                    type: 'section',
                    text: {
                        type: 'mrkdwn',
                        text: `📞 *Huddle Summary*\n\n⏱️ Duration: ${text.split('Duration: ')[1]}`
                    }
                }
            ]
        })
    });

    return response.json();
}

function formatDuration(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    const parts = [];
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

    return parts.join(' ');
}

async function verifySlackSignature(signature, timestamp, body, signingSecret) {
    // Check timestamp is recent (within 5 minutes)
    const time = Math.floor(Date.now() / 1000);
    if (Math.abs(time - parseInt(timestamp)) > 300) {
        return false;
    }

    // Create signature base string
    const sigBaseString = `v0:${timestamp}:${body}`;

    // Create HMAC
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(signingSecret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signatureBytes = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(sigBaseString)
    );

    // Convert to hex
    const hashArray = Array.from(new Uint8Array(signatureBytes));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const computedSignature = `v0=${hashHex}`;

    return computedSignature === signature;
}
