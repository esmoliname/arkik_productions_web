-- Arkik Productions - 003 real configuration seed (idempotent).
-- These are OPERATIONAL DEFAULTS, not demo data: ON CONFLICT DO NOTHING keeps
-- any value an operator edited later.

INSERT INTO config (namespace, key, value) VALUES
  ('logistics', 'limits',
   '{"maxEventsPerDay":2,"bufferHours":5,"minNoticeHours":72,"maxHorizonDays":365,"timeSlots":["08:00","09:00","10:00","11:00","12:00","13:00","14:00","15:00","16:00","17:00","18:00","19:00","20:00","21:00","22:00","23:00"]}'::jsonb),

  ('logistics', 'defaultStatus', '"pendiente"'::jsonb),

  ('sinpe', 'config',
   '{"depositPercentage":0.5,"phone":"+506 6227-4984","cleanPhone":"50662274984","holder":"Juan José Ramírez Chaves","policyText":"El adelanto del 50% vía SINPE Móvil no es reembolsable. Se coordinará reprogramación de fecha sujeta a disponibilidad de agenda (excepto por negligencia o falta de comunicación)."}'::jsonb),

  ('pricing', 'catalog',
   '[{"id":1,"name":"Banda Completa","category":"Música en Vivo","price_crc":650000,"duration":"2 Horas (Duración Estándar)","setup_time_mins":150,"teardown_time_mins":90,"setup_display":"2.5 horas antes","teardown_display":"1.5 horas después"},
     {"id":2,"name":"Cuarteto Arkik","category":"Música en Vivo","price_crc":480000,"duration":"2 Horas (Duración Estándar)","setup_time_mins":120,"teardown_time_mins":60,"setup_display":"2 horas antes","teardown_display":"1 hora después"},
     {"id":3,"name":"Trío Acústico Premium","category":"Música en Vivo","price_crc":380000,"duration":"2 Horas (Duración Estándar)","setup_time_mins":105,"teardown_time_mins":45,"setup_display":"1h 45m antes","teardown_display":"45 min después"},
     {"id":4,"name":"Dúo Íntimo Arkik","category":"Música en Vivo","price_crc":250000,"duration":"2 Horas (Duración Estándar)","setup_time_mins":90,"teardown_time_mins":60,"setup_display":"1.5 horas antes","teardown_display":"1 hora después"},
     {"id":5,"name":"Solista Instrumental","category":"Música en Vivo","price_crc":150000,"duration":"2 Horas (Duración Estándar)","setup_time_mins":60,"teardown_time_mins":30,"setup_display":"1 hora antes","teardown_display":"30 min después"},
     {"id":6,"name":"Alquiler Sonido e Iluminación Pro","category":"Alquiler de Sonido","price_crc":250000,"duration":"Jornada de Evento","setup_time_mins":120,"teardown_time_mins":90,"setup_display":"2 horas antes","teardown_display":"1.5 horas después"}]'::jsonb),

  ('pricing', 'overrides', '{"services":{},"extras":{}}'::jsonb),

  ('pricing', 'rates', '{"extraHourMultiplier":0.5,"travelSurchargeRate":0.12}'::jsonb),

  ('geo', 'provinces',
   '{"San José":["Montes de Oca","Escazú","Santa Ana","Central (San José)","Curridabat","Pérez Zeledón","Desamparados","Moravia","Tibás","Goicoechea","Aserrí","Mora","Vázquez de Coronado"],
     "Alajuela":["Central (Alajuela)","San Carlos","Grecia","Atenas","San Ramón","Palmares","Poás","Orotina"],
     "Cartago":["Central (Cartago)","La Unión (Tres Ríos)","Paraíso","El Guarco","Oreamuno","Alvarado","Turrialba"],
     "Heredia":["Central (Heredia)","Belén","Barva","Santo Domingo","San Rafael","San Isidro","Flores","Sarapiquí"],
     "Guanacaste":["Liberia","Santa Cruz","Nicoya","Carrillo (Playas del Coco)","Cañas","Tilarán","Abangares","La Cruz"],
     "Puntarenas":["Central (Puntarenas)","Garabito (Jacó)","Quepos (Manuel Antonio)","Esparza","Osa (Uvita/Dominical)","Golfito"],
     "Limón":["Central (Limón)","Pococí (Guápiles)","Talamanca (Puerto Viejo/Cahuita)","Siquirres","Matina"]}'::jsonb),

  ('geo', 'gam', '["San José","Heredia","Alajuela","Cartago"]'::jsonb),

  ('geo', 'nonGamExceptions',
   '{"San José":["Pérez Zeledón"],"Heredia":["Sarapiquí"],"Cartago":["Turrialba"]}'::jsonb)
ON CONFLICT (namespace, key) DO NOTHING;
