pragma Ada_2012;

with AUnit.Assertions; use AUnit.Assertions;
with AUnit.Test_Caller;

package body SHA1.Tests is
   package Caller is new AUnit.Test_Caller (Fixture);

   Test_Suite : aliased AUnit.Test_Suites.Test_Suite;

   function Suite return AUnit.Test_Suites.Access_Test_Suite is
      Name : constant String := "[SHA1] ";
   begin
      Test_Suite.Add_Test
        (Caller.Create (Name & "SHA1() - normal", SHA1_Test'Access));
      Test_Suite.Add_Test
        (Caller.Create
           (Name & "SHA1() - one million 'a' characters",
            SHA1_One_Million_Test'Access));

      return Test_Suite'Access;
   end Suite;

   procedure SHA1_Test (Object : in out Fixture) is
   begin
      Assert
        (Hash ("abc") =
         (16#a9#, 16#99#, 16#3e#, 16#36#, 16#47#, 16#06#, 16#81#, 16#6a#,
          16#ba#, 16#3e#, 16#25#, 16#71#, 16#78#, 16#50#, 16#c2#, 16#6c#,
          16#9c#, 16#d0#, 16#d8#, 16#9d#),
         "Hash(`abc`)");
      Assert
        (Hash ("") =
         (16#da#, 16#39#, 16#a3#, 16#ee#, 16#5e#, 16#6b#, 16#4b#, 16#0d#,
          16#32#, 16#55#, 16#bf#, 16#ef#, 16#95#, 16#60#, 16#18#, 16#90#,
          16#af#, 16#d8#, 16#07#, 16#09#),
         "Hash(``) empty string input");
      Assert
        (Hash ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
         (16#84#, 16#98#, 16#3e#, 16#44#, 16#1c#, 16#3b#, 16#d2#, 16#6e#,
          16#ba#, 16#ae#, 16#4a#, 16#a1#, 16#f9#, 16#51#, 16#29#, 16#e5#,
          16#e5#, 16#46#, 16#70#, 16#f1#),
         "Hash(`abcdbcde...`) 448 bits of input");
      Assert
        (Hash
           ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" &
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") =
         (16#a4#, 16#9b#, 16#24#, 16#46#, 16#a0#, 16#2c#, 16#64#, 16#5b#,
          16#f4#, 16#19#, 16#f9#, 16#95#, 16#b6#, 16#70#, 16#91#, 16#25#,
          16#3a#, 16#04#, 16#a2#, 16#59#),
         "Hash(`abcdbcde...`) 896 bits of input");
   end SHA1_Test;

   procedure SHA1_One_Million_Test (Object : in out Fixture) is
      Ctx : Context := Initialize;
   begin
      for I in 1 .. 1_000_000 loop
         Update (Ctx, "a");
      end loop;

      Assert
        (Finalize (Ctx) =
         (16#34#, 16#aa#, 16#97#, 16#3c#, 16#d4#, 16#c4#, 16#da#, 16#a4#,
          16#f6#, 16#1e#, 16#eb#, 16#2b#, 16#db#, 16#ad#, 16#27#, 16#31#,
          16#65#, 16#34#, 16#01#, 16#6f#),
         "check hashing result");
   end SHA1_One_Million_Test;
end SHA1.Tests;
