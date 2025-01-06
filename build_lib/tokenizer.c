char *toLower(char* input)
{
    char *temp = malloc((int)strlen(input));
    for(int i=0; i < (int)strlen(input) ; i++)
    {
        temp[i] = tolower(input[i]);
    } 
    return temp;
}

u_char *urlDecode(u_char *str) 
{
  int d = 0; /* whether or not the string is decoded */

  u_char *dStr = malloc(strlen((const char*)str) + 1);
  u_char eStr[] = "00"; /* for a hex code */

  strcpy((char*)dStr, (char*)str);

  while(!d) {
    d = 1;
    int i; /* the counter for the string */
    int len_dStr = strlen((const char*)dStr);

    for(i=0;i<len_dStr;++i) {

      if(dStr[i] == '%') {
        if(dStr[i+1] == 0)
          return dStr;

        if(isxdigit(dStr[i+1]) && isxdigit(dStr[i+2])) {

          d = 0;

          /* combine the next to numbers into one */
          eStr[0] = dStr[i+1];
          eStr[1] = dStr[i+2];

          /* convert it to decimal */
          long int x = strtol((char*)eStr, NULL, 16);

          /* remove the hex */
          memmove(&dStr[i+1], &dStr[i+3], strlen((char*)&dStr[i+3])+1);

          dStr[i] = x;
        }
      }
    }
  }

  return dStr;
}

int isInString(char* input, int len, char c)
{
    for(int i=0; i< len; i++)
    {
        if(c == input[i])
            return 1;
    }
    return 0;
}
int isInArr(char* input, char arr[2500][100], int len)
{
    for(int i=0 ; i < len; i++){
        if(strncasecmp(input,arr[i],(int)strlen(input))==0)
            return 1;
    }
    return 0;
}
int isPathTransform(char* input, int len)
{
    char *pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    int flag = 1;
    int i=0;
    while( flag == 1 && i < len){
        for(int j=0; j < (int)strlen(pattern); j++ ){
            int result = isInString(pattern,strlen(pattern),input[i]);
            if(result == 0)
                flag = 0;
        }
        i++;
    }
    return flag;
}
/*int isUrlEncoded(char *input, int len)
{
    const char *pattern = "0123456789abcdefABCDEF"
    for(int i=0; i< len; i++)
    {
        if(input[i] == '%' && i > (len-2))
        {
            if(isInString(input[i+1], pattern) && isInString(input[i+2],pattern))
                return 1;
        }
    }
    return 0;
}*/
int isPureString(char* input, int len)
{
    char *pattern = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-";
    for(int i=0; i < len; i++)
    {
        if(!isInString(pattern, strlen(pattern), input[i]))
           return 0;
    }
    return 1;

}
int isHexString(char* input, int len)
{
    char *pattern = "0123456789abcdefABCDEF";
    /*if((int)strlen(input)%2!=0)
        return 0;
    int flag = 1;
    char *pattern = "0123456789abcdefABCDEF";
    int i=0;
    while( flag == 1 && i < len){
        for(int j=0; j < (int)strlen(pattern); j++ ){
            int result = isInString(pattern,(int)strlen(pattern),input[i]);
            if(result==0)
                flag = 0;
        }
        i++;
    }
    return flag;*/
    for(int i=0; i < len; i++)
    {
        if(!isInString(pattern, strlen(pattern), input[i]))
           return 0;
    }
    return 1;
}

int isUniString(char* input, int len)
{
    for(int i=0; i < len; i++)
    {
        if((int)input[i] < 32)
            return 1;
    }
    return 0;
}

int isSenString(char* input, char KEYWORDS_IN_TRAINING[100][20]){
    for(int i=0; i < 82; i++)
    {
        if(strlen(KEYWORDS_IN_TRAINING[i]) != strlen(input))
            return 0;
        if(strncasecmp(input,KEYWORDS_IN_TRAINING[i],(int)strlen(input))==0)
        {
            return 1;
        }
    }
    return 0;
}

int isNumber(char* input, int len)
{
    char *pattern = "0123456789";
    for(int i=0; i < len; i++)
    {
        if(!isInString(pattern,10,input[i]))
            return 0;
    }
    return 1;
}

int len_of_string(char* input)
{
    int i;
    for(i=0; input[i] != '\0'; ++i);
    return i;
}

int count_slash(char* path, int len)
{
    int count=0;
    for(int i= 0;i < len; i++)
    {
        if(path[i] == '/')
            count++;
    }
    return count;
}
void handle_path(char *parsed_path, char* path, int len, char* punctuations)
{
    parsed_path[0] = '/';
    parsed_path[1] = ' ';
    int k = 2;
    for(int i=1; i< len; i++)
    {
        if(isInString(punctuations, 29, path[i]))
        {
            parsed_path[k] = ' ';
            parsed_path[k+1] = path[i];
            parsed_path[k+2] = ' ';
            k = k+3;
        }
        else{
            parsed_path[k] = path[i];
            k++;
        }
    }
    parsed_path[k] = ' ';
    parsed_path[k+1] = '?';
    parsed_path[k+2] = '\0';
}

void handle_data(char* parsed_data, char* data, int len, char* punctuations)
{
    //char *parsed_data = malloc(1000);
    //parsed_data[0] = '?';
    parsed_data[0] = ' ';
    int k = 1;
    for(int i = 0; i< len; i++)
    {
        if(isInString(punctuations, 29, data[i]))
        {
            parsed_data[k] = ' ';
            parsed_data[k+1] = data[i];
            parsed_data[k+2] = ' ';
            k = k+3;
        }
        else{
            parsed_data[k] = data[i];
            k++;
        }
    }
    parsed_data[k] = '\0';
}

int find_position_of_str(char pattern[320][100], char* str, int len)
{
    int i;
    for(i=0; i< len; i++)
    {
        if(strncasecmp(pattern[i],str,(int)strlen(str))==0)
        {
            return i +1;
            
         }
    }
    return -1;
}

void tokenizer_path(int *token_arr, char* parsed_path, char pattern[320][100], int len, char *punctuations, char ext[2445][100], int len_ext, int *len_path_arr)
{
    //int *token_arr = malloc(100);
    int i = 0;
    int position_pathstring = find_position_of_str(pattern, "pathstring", len);
    //int position_slash = find_position_of_str(pattern, "/", len);
    int position_purestring = find_position_of_str(pattern, "purestring", len);
    char* token = strtok(parsed_path," ");
    char* pre_string = NULL;
    while( token != NULL ) {
     if((int)strlen(token)==1 && isInString(punctuations, 29, token[0]))
        {
            token_arr[i] = find_position_of_str(pattern, token , len);
        }
     else if(isInArr(token,ext,len_ext) && pre_string != NULL && (pre_string[0]=='.'))
     {
         int position_ext = find_position_of_str(pattern, token, len);
         if(position_ext==-1)
            position_ext = find_position_of_str(pattern, token, len);
         if(position_ext==-1)
            token_arr[i] = position_purestring;
         else
            token_arr[i] = position_ext;
     }
     else
     {
        token_arr[i] = position_pathstring;
     }
     i++;
     if(pre_string != NULL)
        free(pre_string);
     pre_string = malloc((int)strlen(token)+1);
     pre_string = memcpy(pre_string,token,(int)strlen(token));
     token = strtok(NULL, " ");
    *len_path_arr = i;
    }

}

void tokenizer_data(int *token_arr, char* parsed_data, char pattern[320][100], int len, int *len_path_arr, char *punctuations, char KEYWORDS_IN_TRAINING[100][20])
{
    //int *token_arr = malloc(100);
    //char serve_token_arr[100][100];
    int i = 0;
    int position_purestring = find_position_of_str(pattern, "purestring", len);
    int position_unistring = find_position_of_str(pattern, "unistring", len);
    int position_hexstring = find_position_of_str(pattern, "hexstring", len);
    //int position_senstring = find_position_of_str(pattern, "senstring", len);
    int position_number = find_position_of_str(pattern, "numbers", len);
    int position_mixstring = find_position_of_str(pattern, "mixstring", len);

    char* token = strtok(parsed_data," ");
    while(token != NULL ) {
        if((int)strlen(token)==1 && isInString(punctuations,29, token[0]))
        {
            fprintf(stderr,"\nfound=%s",token);
            token_arr[i] = 
            find_position_of_str(pattern, token, len);
            printf("\nfound=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else if(isSenString(token,KEYWORDS_IN_TRAINING))
        {
            //fprintf(stderr,"\nsen=%s",token);
            token_arr[i] = find_position_of_str(pattern, token, len);
            //printf("\nsen=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else if(isNumber(token,(int)strlen(token)))
        {
            //fprintf(stderr,"\nnumber=%s",token);
            token_arr[i] = position_number;
            printf("\nnumber=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else if(isHexString(token,(int)strlen(token)))
        {
            //fprintf(stderr,"\nhex=%s",token);
            token_arr[i] = position_hexstring;
            //printf("\nhex=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else if(isPureString(token,(int)strlen(token)))
        {
            //fprintf(stderr,"pure=%s",token);
            token_arr[i] = position_purestring;
            //printf("\npure=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else if(isUniString(token,(int)strlen(token)))
        {
            //fprintf(stderr,"\nuni=%s",token);
            token_arr[i] = position_unistring;
            printf("\nuni=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        else
        {
            //fprintf(stderr,"\nmix=%s",token);
            token_arr[i] = position_mixstring;
            //printf("\nmix=%i",token_arr[i]);
            i++;
            token = strtok(NULL, " ");
    	    *len_path_arr = i;
            continue;
        }
        
    }
    //return token_arr;
}