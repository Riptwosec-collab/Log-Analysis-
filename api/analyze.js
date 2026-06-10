export default function handler(req,res){
 if(req.method!=='POST')return res.status(405).json({error:'Method not allowed'});
 const b=typeof req.body==='string'?JSON.parse(req.body||'{}'):(req.body||{});
 const log=String(b.log||'');
 if(!log.trim())return res.status(400).json({error:'Please input log first'});
 const lines=log.split(/\n/).filter(Boolean).length;
 const low=log.toLowerCase();
 const keys=['error','fail','failed','deny','denied','timeout','critical','down','unauthorized','blocked'];
 const hits=keys.filter(k=>low.includes(k));
