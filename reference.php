<?php

/**
 * This file is used as a reference when updating the plugin.
 * It should properly highlight an error on each line where there is an error identifier in the comments.
 */

use Domain\UseCase;
use Domain\UseCaseInterface;

class HelloWorld extends UseCase implements UseCaseInterface
{
	private PDOStatement $query; #property.onlyRead

	private static int $o; #property.onlyWritten

	private $a; #missingType.property #property.unused

	private int $b; #property.onlyWritten

	private readonly string $adefdedefde; #property.uninitializedReadonly #property.onlyRead

	public function __construct(PDO $db) #constructor.missingParentCall #constructor.unusedParameter
	{
		dump($this->adefdedefde); #property.uninitializedReadonly

		$this->b = 1;

		self::$o = '1'; #assign.propertyType
	}

 	private function bb($a): array #missingType.parameter #method.unused #missingType.iterableValue
 	{
 		self::$o = 1;

 		$this->execute(1); #argument.type

		return $a;
	}

	private function execute(array $a) #method.visibility #missingType.iterableValue #missingType.return
	{
		$this->b = '1'; #assign.propertyType

		return $a;
	}
}
