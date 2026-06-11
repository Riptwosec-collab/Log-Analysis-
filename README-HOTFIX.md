# HOTFIX

สาเหตุ Build Failed:
- ใน `lib/logAnalyzer.ts` มี comma เกิน 1 ตัวก่อน rule `Credential Dumping Indicator`
- ทำให้ TypeScript มอง array `rules` ว่ามี element เป็น `undefined`
- Error ที่เกิดได้: Type 'undefined' is not assignable to type 'Rule'

แก้แล้ว:
- ลบ comma เกินหลัง object `Routing: Adjacency Down`
- ตรวจ `tsc --noEmit --strict lib/logAnalyzer.ts` ผ่านแล้ว

วางทับ:
- `lib/logAnalyzer.ts`
- `app/page.tsx`
- `data/ioc.json`

แล้ว commit เพื่อให้ Vercel deploy ใหม่
