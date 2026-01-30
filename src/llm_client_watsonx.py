import os
from dotenv import load_dotenv
from litellm import completion
import litellm

load_dotenv()


class LLMClient:
    def __init__(self, model_full_name=None):
        if model_full_name:
            self.model = model_full_name    
        else:
            self.model = os.getenv("LLM_PROVIDER", "watsonx") + "/" + os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
        
        self.api_key = os.getenv("WATSONX_APIKEY")
        self.project_id = os.getenv("WATSONX_PROJECT_ID")
        self.url = os.getenv("WATSONX_URL")


    def generate_response(self, messages, **kwargs):
        """
        Generate a response using the LiteLLM completion API.

        Args:
            messages: List of message dictionaries
            **kwargs: Additional parameters for the completion call

        Returns:
            Response from the LLM
        """
        kwargs.setdefault("temperature", float(os.getenv("TEMPERATURE_ONLINE", 0)))
        
        max__tokens_llm_defined = litellm.get_max_tokens(self.model)
        watsonx_max_tokens = int(os.getenv("WATSONX_MAX_TOKENS", 10000))
        if max__tokens_llm_defined > watsonx_max_tokens:
            max__tokens_llm_defined = watsonx_max_tokens  # WatsonX limitation
        
        try:
            response = completion(
                model=self.model,
                messages=messages,
                api_key=self.api_key,
                base_url=self.url,
                project_id=self.project_id,
                max_tokens=max__tokens_llm_defined,  #
                # max_input_tokens=60000, 
                **kwargs,
            )
            return response.choices[0].message.content

        except Exception as e:
            raise Exception(f"Error generating LLM response: {str(e)}")
