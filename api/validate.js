import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { licenseKey, hwid, action, deviceInfo } = req.body;
        const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        if (!licenseKey || !hwid) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields' 
            });
        }

        // Busca a licença
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('*')
            .eq('license_key', licenseKey.toUpperCase())
            .single();

        if (licenseError || !license) {
            await logUsage(null, hwid, 'INVALID_KEY', { key: licenseKey }, clientIp, userAgent);
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid license key',
                code: 'INVALID_KEY'
            });
        }

        // Verifica se está ativa
        if (!license.is_active) {
            await logUsage(license.id, hwid, 'DEACTIVATED', {}, clientIp, userAgent);
            return res.status(403).json({ 
                success: false, 
                error: 'License has been deactivated',
                code: 'DEACTIVATED'
            });
        }

        // Verifica expiração
        if (license.expires_at && new Date(license.expires_at) < new Date()) {
            await logUsage(license.id, hwid, 'EXPIRED', {}, clientIp, userAgent);
            return res.status(403).json({ 
                success: false, 
                error: 'License has expired',
                code: 'EXPIRED'
            });
        }

        // Verifica/registra dispositivo
        const { data: existingDevice } = await supabase
            .from('authorized_devices')
            .select('*')
            .eq('license_id', license.id)
            .eq('hwid', hwid)
            .single();

        if (existingDevice) {
            if (existingDevice.is_blocked) {
                await logUsage(license.id, hwid, 'BLOCKED_DEVICE', {}, clientIp, userAgent);
                return res.status(403).json({ 
                    success: false, 
                    error: 'This device has been blocked',
                    code: 'BLOCKED_DEVICE'
                });
            }
            
            await supabase
                .from('authorized_devices')
                .update({ last_seen_at: new Date().toISOString() })
                .eq('id', existingDevice.id);
        } else {
            const { count } = await supabase
                .from('authorized_devices')
                .select('*', { count: 'exact', head: true })
                .eq('license_id', license.id)
                .eq('is_blocked', false);

            if (count >= license.max_devices) {
                await logUsage(license.id, hwid, 'DEVICE_LIMIT', { count }, clientIp, userAgent);
                return res.status(403).json({ 
                    success: false, 
                    error: `Device limit reached (${license.max_devices})`,
                    code: 'DEVICE_LIMIT'
                });
            }

            await supabase
                .from('authorized_devices')
                .insert({
                    license_id: license.id,
                    hwid: hwid,
                    device_info: deviceInfo || {}
                });

            await supabase
                .from('licenses')
                .update({ devices_used: (count || 0) + 1 })
                .eq('id', license.id);
        }

        await supabase
            .from('licenses')
            .update({ last_used_at: new Date().toISOString() })
            .eq('id', license.id);

        await logUsage(license.id, hwid, action || 'VALIDATE', {}, clientIp, userAgent);

        const response = {
            success: true,
            user: license.user_name,
            expiresAt: license.expires_at,
            token: generateSessionToken(license.id, hwid)
        };

        return res.status(200).json(response);

    } catch (error) {
        console.error('Validation error:', error);
        return res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
}

async function logUsage(licenseId, hwid, action, details, ip, userAgent) {
    try {
        await supabase
            .from('usage_logs')
            .insert({
                license_id: licenseId,
                hwid: hwid,
                action: action,
                details: details,
                ip_address: ip,
                user_agent: userAgent
            });
    } catch (e) {
        console.error('Log error:', e);
    }
}

function generateSessionToken(licenseId, hwid) {
    const data = {
        lid: licenseId,
        hwid: hwid,
        ts: Date.now(),
        exp: Date.now() + (60 * 60 * 1000)
    };
    return Buffer.from(JSON.stringify(data)).toString('base64');
}
