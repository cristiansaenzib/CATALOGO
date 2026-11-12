-- IZAN: asignar el usuario principal como administrador
-- Ejecutar en Supabase > SQL Editor con el proyecto correcto.
DO $$
DECLARE v_user_id uuid;
BEGIN
  SELECT id INTO v_user_id
  FROM auth.users
  WHERE lower(email) = lower('saenz1098@gmail.com')
  LIMIT 1;

  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'No existe el usuario % en Authentication > Users. Verifica el correo y el proyecto.', 'saenz1098@gmail.com';
  END IF;

  INSERT INTO public.admins(user_id)
  VALUES (v_user_id)
  ON CONFLICT (user_id) DO NOTHING;
END $$;

-- Debe devolver saenz1098@gmail.com
SELECT u.email AS administrador_confirmado
FROM auth.users u
JOIN public.admins a ON a.user_id = u.id
WHERE lower(u.email) = lower('saenz1098@gmail.com');
