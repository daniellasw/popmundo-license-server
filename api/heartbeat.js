import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ valid: false });
        }

        let tokenData;
        try {
            tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
        } catch {
            return res.status(401).json({ valid: false, reason: 'INVALID_TOKEN' });
        }

        if (tokenData.exp < Date.now()) {
            return res.status(401).json({ valid: false, reason: 'TOKEN_EXPIRED' });
        }

        const { data: license } = await supabase
            .from('licenses')
            .select('is_active, expires_at')
            .eq('id', tokenData.lid)
            .single();

        if (!license) {
            return res.status(401).json({ valid: false, reason: 'LICENSE_NOT_FOUND' });
        }

        if (!license.is_active) {
            return res.status(403).json({ valid: false, reason: 'LICENSE_DEACTIVATED' });
        }

        if (license.expires_at && new Date(license.expires_at) < new Date()) {
            return res.status(403).json({ valid: false, reason: 'LICENSE_EXPIRED' });
        }

        const { data: device } = await supabase
            .from('authorized_devices')
            .select('is_blocked')
            .eq('license_id', tokenData.lid)
            .eq('hwid', tokenData.hwid)
            .single();

        if (device && device.is_blocked) {
            return res.status(403).json({ valid: false, reason: 'DEVICE_BLOCKED' });
        }

        const newToken = Buffer.from(JSON.stringify({
            ...tokenData,
            exp: Date.now() + (60 * 60 * 1000)
        })).toString('base64');

        return res.status(200).json({ 
            valid: true,
            newToken: newToken
        });

    } catch (error) {
        console.error('Heartbeat error:', error);
        return res.status(500).json({ valid: false, reason: 'SERVER_ERROR' });
    }
}
