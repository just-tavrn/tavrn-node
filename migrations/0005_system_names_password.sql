-- Standard-Channels und -Kategorien tragen einen Systemnamen, den Clients lokalisieren,
-- bis ein Berechtigter sie umbenennt (dann NULL).
ALTER TABLE channels ADD COLUMN system_name TEXT;
ALTER TABLE categories ADD COLUMN system_name TEXT;
