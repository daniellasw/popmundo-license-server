import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY
);

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

    try {
        const { token, module } = req.body;
        
        if (!token || !module) {
            return res.status(400).json({ error: 'Missing token or module' });
        }

        let tokenData;
        try {
            tokenData = JSON.parse(Buffer.from(token, 'base64').toString());
        } catch {
            return res.status(401).json({ error: 'Invalid token' });
        }

        if (tokenData.exp < Date.now()) {
            return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
        }

        const { data: license } = await supabase
            .from('licenses')
            .select('is_active')
            .eq('id', tokenData.lid)
            .single();

        if (!license || !license.is_active) {
            return res.status(403).json({ error: 'License invalid' });
        }

        const { data: codeData, error } = await supabase
            .from('protected_code')
            .select('code_content, version')
            .eq('module_name', module)
            .eq('is_active', true)
            .single();

        if (error || !codeData) {
            return res.status(404).json({ error: 'Module not found' });
        }

        await supabase.from('usage_logs').insert({
            license_id: tokenData.lid,
            hwid: tokenData.hwid,
            action: 'LOAD_MODULE',
            details: { module, version: codeData.version }
        });

        const encodedCode = Buffer.from(codeData.code_content).toString('base64');
        
        return res.status(200).json({
            success: true,
            code: encodedCode,
            version: codeData.version
        });

    } catch (error) {
        console.error('Get code error:', error);
        return res.status(500).json({ error: 'Server error' });
    }
}
